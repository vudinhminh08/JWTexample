package vn.mbf.cbs.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import vn.mbf.cbs.auth.common.Const;
import vn.mbf.cbs.auth.common.CustomResultCode;
import vn.mbf.cbs.auth.dto.*;
import vn.mbf.cbs.auth.entity.AmAccessTimeDtl;
import vn.mbf.cbs.auth.entity.AmGroupUser;
import vn.mbf.cbs.auth.entity.AmUser;
import vn.mbf.cbs.auth.exception.CommandFailureException;
import vn.mbf.cbs.auth.message.Message;
import vn.mbf.cbs.auth.properties.SsoProperties;
import vn.mbf.cbs.auth.repository.AmGroupUserRepository;
import vn.mbf.cbs.auth.repository.AmUserRepository;
import vn.mbf.cbs.auth.util.DateUtil;
import vn.mbf.cbs.auth.util.JwtUtil;
import vn.mbf.cbs.lib.log.common.Utils;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static vn.mbf.cbs.auth.util.DateUtil.checkTheTimeInterval;

@Service
@AllArgsConstructor
@Slf4j
public class AuthService {

    private TokenService tokenService;
    private CacheService cacheService;
    private AmUserRepository amUserRepository;
    private AmGroupUserRepository amGroupUserRepository;
    private PasswordEncoder passwordEncoder;
    private RestTemplate restSsoTemplate;
    private SsoProperties ssoProperties;
    private ModelMapper modelMapper;
    private HazelcastInstance hazelcastInstance;

    @Autowired
    Message message;

    /**
     * Sign in with username/password
     *
     * @param loginRequestDto
     * @return
     * @throws IOException
     */
    public Optional<TokenDto> signIn(LoginRequestDto loginRequestDto, HttpServletRequest request) throws Exception {

        Optional<AmUser> amUserOptional = amUserRepository
                .findTopByUserName(loginRequestDto.getUserName().toUpperCase());

        IMap<String, String> mPolicy = hazelcastInstance.getMap(Const.DFT.POLICY_LOGIN);
        IMap<Long, List<AmAccessTimeDtl>> mUserAccessTime = hazelcastInstance.getMap(Const.DFT.POLICY_USER_ACCESS_TIME);
        IMap<Long, List<AmAccessTimeDtl>> mGroupAccessTime = hazelcastInstance.getMap(Const.DFT.POLICY_GROUP_ACCESS_TIME);
        IMap<Long, List<AmAddrUserDto>> mUserAddr = hazelcastInstance.getMap(Const.DFT.POLICY_USER_ADDR);
        IMap<Long, List<AmAddrGroupDto>> mGroupAddr = hazelcastInstance.getMap(Const.DFT.POLICY_GROUP_ADDR);

        TokenDto tokenDto = null;
        if (amUserOptional.isPresent()) {
            AmUser amUser = amUserOptional.get();

            // get groupId by userId
            List<AmGroupUser> amGroupUsers = amGroupUserRepository.findByUserId(amUser.getUserId());

            // check status
            if (amUser.getStatus() == 1
                    && passwordEncoder.matches(loginRequestDto.getPassword(), amUser.getPassword())) {

                String accessToken = tokenService.generateToken(amUser, null);

                tokenDto = TokenDto.builder().type("Bearer").accessToken(accessToken)
                        .info(modelMapper.map(amUser, CbsUserDto.class)).build();

                // check login session
                String maxOpenSessionUser = mPolicy.get(Const.DFT.MAX_OPEN_SESSION_USER);
                if (maxOpenSessionUser != null) {
                    int maxOpenSession = Integer.parseInt(maxOpenSessionUser);
                    if (maxOpenSession <= cacheService.countSession(amUser.getUserId())) {
                        throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1006,
                                message.getMessage(CustomResultCode.Code.AUTH_ERR_1006), HttpStatus.UNAUTHORIZED);
                    }
                }

                // check ip
                if (!checkRoleAddressIp(amUser, mUserAddr, mGroupAddr, amGroupUsers, request)) {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1005,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1005), HttpStatus.UNAUTHORIZED);
                }

                // check date lock account
                if (amUser.getLockedDate() != null
                        && amUser.getLockedDate().before(new Date())) {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1001,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1001), HttpStatus.UNAUTHORIZED);
                }

                // kiểm tra mật khẩu hết hạn
                if (checkPasswordExpire(amUser, mPolicy)) {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1003,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1003), HttpStatus.UNAUTHORIZED);

                }

                // kiểm tra thời gian truy cập hợp lệ
                if (!checkAccessTime(amUser, mUserAccessTime, mGroupAccessTime, amGroupUsers)) {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1004,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1004), HttpStatus.UNAUTHORIZED);
                }
            } else {

                // kiểm tra số lần đăng nhập sai
                if (checkLoginFailure(amUser, mPolicy)) {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1001,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1001), HttpStatus.UNAUTHORIZED);
                } else {
                    throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1002,
                            message.getMessage(CustomResultCode.Code.AUTH_ERR_1002), HttpStatus.UNAUTHORIZED);
                }
            }

            // update faild_count = 0
            amUser.setFailureCount(0);
            amUserRepository.save(amUser);
        } else {

            throw new CommandFailureException(CustomResultCode.Code.AUTH_ERR_1002,
                    message.getMessage(CustomResultCode.Code.AUTH_ERR_1002), HttpStatus.UNAUTHORIZED);
        }
        return Optional.ofNullable(tokenDto);
    }

    /**
     * Sign in with SSO
     *
     * @param ssoRequestDto
     * @return
     */
    public Optional<TokenDto> signInSso(@Valid SsoRequestDto ssoRequestDto) {

        TokenDto tokenDto = null;

        String uriUserInfo = String.format(ssoProperties.getUrl(), ssoRequestDto.getAuthorizationCode(),
                ssoRequestDto.getRedirectUri());

        // Header basic auth
        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(ssoProperties.getEncodedCredentials());
        //headers.setBasicAuth(ssoProperties.getClientId(), ssoProperties.getClientPassword());

        HttpEntity<Map<String, Object>> request = new HttpEntity<Map<String, Object>>(null, headers);

        // call sso
        SsoResponseDto ssoResponseDto = restSsoTemplate.postForEntity(uriUserInfo, request,
                        SsoResponseDto.class)
                .getBody();

        // success
        if (ssoResponseDto.getTokenId() != null) {

            try {
                JsonNode jwtNode = JwtUtil.decode(ssoResponseDto.getTokenId());

                String username = jwtNode.get("username").asText();
                int exp = jwtNode.get("exp").asInt();

                Optional<AmUser> amUserOptional = amUserRepository
                        .findTopByUserName(username.toUpperCase());

                // is User exists
                if (amUserOptional.isPresent()) {
                    AmUser amUser = amUserOptional.get();

                    // check status
                    if (amUser.getStatus() == 1) {
                        String accessToken = tokenService.generateToken(amUser, exp);

                        tokenDto = TokenDto.builder().type("Bearer").accessToken(accessToken)
                                .info(modelMapper.map(amUser, CbsUserDto.class)).build();
                    }
                }
            } catch (Exception e) {
                log.warn("error decode jwt: {}", ssoResponseDto.getTokenId(), e);
            }
        } else {
            log.error("request sso error: {}, {}", ssoRequestDto, ssoResponseDto);
        }

        return Optional.ofNullable(tokenDto);
    }

    /**
     * Logout
     *
     * @param token
     * @param cbsUser
     */
    public void logout(String token, CbsUserDto cbsUser) {

        cacheService.deleteCache(token, cbsUser);
    }

    /**
     * @param amUser
     * @param mPolicy
     * @return
     */
    public boolean checkLoginFailure(AmUser amUser, IMap<String, String> mPolicy) {
        // update FailureCount
        boolean isCheck = false;
        if (amUser.getFailureCount() != null) {
            amUser.setFailureCount(amUser.getFailureCount() + 1);
        } else {
            amUser.setFailureCount(1);
        }
        amUserRepository.save(amUser);

        // check LoginFailureCount
        int failCount = amUser.getFailureCount();

        String maxLoginFailure = mPolicy.get(Const.DFT.MAX_LOGIN_FAILURE);

        if (maxLoginFailure != null) {
            int maxLoginFailCount = Integer.parseInt(maxLoginFailure);
            if (failCount >= maxLoginFailCount) {
                // update date lock account
                amUser.setLockedDate(new Date());
                amUserRepository.save(amUser);
                isCheck = true;
            }
        }

        return isCheck;
    }

    /**
     * @param amUser
     * @param mPolicy
     * @return
     */
    public boolean checkPasswordExpire(AmUser amUser, IMap<String, String> mPolicy) {
        // check password expire
        boolean isCheck = false;
        Date modifiedPassword = amUser.getModifiedPassword();
        String passwordExpireDuration = mPolicy.get(Const.DFT.PASSWORD_EXPIRE_DURATION);
        if (passwordExpireDuration != null && modifiedPassword != null) {
            int dateExpire = Integer.parseInt(passwordExpireDuration);
            DateUtil dateUtil = new DateUtil();
            Date datePasswordExpire = dateUtil.datePasswordExpire(modifiedPassword, dateExpire);
            if (datePasswordExpire.before(new Date())) {
                isCheck = true;
            }
        }
        return isCheck;
    }

    /**
     * @param amUser
     * @param mUserAccessTime
     * @param mGroupAccessTime
     * @throws Exception
     */
    public boolean checkAccessTime(AmUser amUser,
                                   IMap<Long, List<AmAccessTimeDtl>> mUserAccessTime,
                                   IMap<Long, List<AmAccessTimeDtl>> mGroupAccessTime,
                                   List<AmGroupUser> amGroupUsers) throws Exception {
        boolean isCheck = false;

        // check access time
        Date dateCurrent = new Date();
        int dayId = dateCurrent.getDay() + 1;
        List<AmAccessTimeDtl> amAccessTimeUserDtls = mUserAccessTime.get(amUser.getUserId());

        boolean checkExistsUser = false;
        boolean checkExistsGroup = true;

        if (amAccessTimeUserDtls == null) {
            checkExistsUser = true;
        }

        for (AmGroupUser amGroupUser : amGroupUsers) {
            List<AmAccessTimeDtl> amAccessTimeGroupDtls = mGroupAccessTime.get(amGroupUser.getGroupId());
            if (amAccessTimeGroupDtls != null) {
                checkExistsGroup = false;
            }
        }

        //check user và group null
        if (checkExistsUser && checkExistsGroup) {
            return true;
        }

        //check user access time
        if ((amAccessTimeUserDtls != null
                && checkRoleAccessTime(amAccessTimeUserDtls, dayId, dateCurrent))) {
            isCheck = true;
        }

        //check group access time
        for (AmGroupUser amGroupUser : amGroupUsers) {

            List<AmAccessTimeDtl> amAccessTimeGroupDtls = mGroupAccessTime.get(amGroupUser.getGroupId());

            if (amAccessTimeGroupDtls != null &&
                    checkRoleAccessTime(amAccessTimeGroupDtls, dayId, dateCurrent)) {
                isCheck = true;
            }
        }
        return isCheck;
    }

    /**
     *
     * @param amAccessTimeDtls
     * @param dayId
     * @param dateCurrent
     * @return
     * @throws Exception
     */
    public boolean checkRoleAccessTime(List<AmAccessTimeDtl> amAccessTimeDtls,
                                       int dayId, Date dateCurrent) throws Exception {
        for (AmAccessTimeDtl amAccessTimeDtl : amAccessTimeDtls) {
            if (dayId == amAccessTimeDtl.getDayId() &&
                    checkTheTimeInterval(amAccessTimeDtl.getStartTime(), amAccessTimeDtl.getEndTime(), dateCurrent)) {
                return true;
            }
        }
        return false;
    }

    /**
     *
     * @param amUser
     * @param mUserAddr
     * @param request
     * @return
     */
    public boolean checkRoleAddressIp(AmUser amUser,
                                      IMap<Long, List<AmAddrUserDto>> mUserAddr,
                                      IMap<Long, List<AmAddrGroupDto>> mGroupAddr,
                                      List<AmGroupUser> amGroupUsers,
                                      HttpServletRequest request) {

        List<AmAddrUserDto> amAddrUserDtos = mUserAddr.get(amUser.getUserId());
        boolean checkAddrUserExists = false;
        boolean checkAddrGroupExists = true;

        // check address IP user exists
        if (amAddrUserDtos == null) {
            checkAddrUserExists = true;
        }

        // check address IP group exists
        if (amGroupUsers != null) {
            for (AmGroupUser amGroupUser : amGroupUsers) {
                List<AmAddrGroupDto> amAddrGroupDtos = mGroupAddr.get(amGroupUser.getGroupId());
                if (amAddrGroupDtos != null) {
                    checkAddrGroupExists = false;
                }
            }
        }

        if (checkAddrUserExists && checkAddrGroupExists) {
            return true;
        }
        String ipAddressRemote= Utils.getClientIp(request);
        if (amAddrUserDtos != null && amAddrUserDtos.size()>0) {
            for (AmAddrUserDto addrUserDto : amAddrUserDtos) {
                if (addrUserDto != null && addrUserDto.getAddress()!=null && addrUserDto.getAddress().equals(ipAddressRemote)) {
                    return true;
                }
            }
        }

        for (AmGroupUser amGroupUser : amGroupUsers) {
            List<AmAddrGroupDto> amAddrGroupDtos = mGroupAddr.get(amGroupUser.getGroupId());
            if (amAddrGroupDtos != null) {
                for (AmAddrGroupDto addrGroupDto : amAddrGroupDtos) {
                    if (addrGroupDto != null
                            && ((request != null
                            && addrGroupDto.getAddress().equals(request.getLocalAddr())
                            && addrGroupDto.getGrantType() == Const.DFT.POLICY_GRANT_TYPE_ALLOW)
                            || (request != null && addrGroupDto.getAddress() == null))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
