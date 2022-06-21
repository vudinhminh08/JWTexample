package vn.mbf.cbs.auth.service;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMethod;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.HazelcastJsonValue;
import com.hazelcast.map.IMap;
import com.hazelcast.query.Predicates;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import vn.mbf.cbs.auth.common.Const;
import vn.mbf.cbs.auth.dto.CbsUserDto;
import vn.mbf.cbs.auth.dto.MenuDto;
import vn.mbf.cbs.auth.entity.AmRestApi;
import vn.mbf.cbs.auth.properties.TokenProperties;
import vn.mbf.cbs.auth.util.RequestMethodUtil;

@Service
@AllArgsConstructor
@Slf4j
public class CacheService {

	private HazelcastInstance hazelcastInstance;
	
	private ObjectMapper objectMapper;
	
	private TokenProperties tokenProperties;
	
	/**
	 * Evict
	 * 
	 * @param token
	 * @param username
	 */
	public void deleteCache(String token, CbsUserDto cbsUser) {
		
		StringBuilder builder = new StringBuilder();
		builder.append("delete cache: " + cbsUser.toString());
		
		boolean result = true;
		
		// clear token cache
		try {
			IMap<String, String> mToken = hazelcastInstance.getMap(Const.DFT.TOKEN);
			mToken.delete(token);
		} catch (Exception e) {
			result = false;
		}
		builder.append(", token=" + result);
        
		result = true;
        // clear authorization cache
		// TODO: can check user logout toan bo session moi xoa cache authorization
        try {
        	IMap<Long, HashMap<String, String>> mAuth = hazelcastInstance.getMap(Const.DFT.AUTHORIZATION);
            mAuth.delete(cbsUser.getId());
        } catch (Exception e) {
        	result = false;
        }
        builder.append(", authorization=" + result);
        
        result = true;
		// clear <token, user_id> cache
        try {
        	IMap<String, HazelcastJsonValue> mUser = hazelcastInstance.getMap(Const.DFT.USER_TOKEN);
            mUser.delete(token);
        } catch (Exception e) {
        	result = false;
        }
        builder.append(", user_token=" + result);
        
        // add token to logout cache
        try {
        	IMap<String, String> mLogout = hazelcastInstance.getMap(Const.DFT.LOGOUT);
            mLogout.put(token, objectMapper.writeValueAsString(cbsUser));
        } catch (Exception e) {
        	log.error("error", e);
        }
        
        log.info(builder.toString());
	}
	
	/**
	 * Cache token
	 * 
	 * @param token
	 * @param cbsUserDto
	 * @param userId
	 */
	public void cacheToken(String token, CbsUserDto cbsUserDto, Long userId) {
    	
        try {
        	IMap<String, String> mToken = hazelcastInstance.getMap(Const.DFT.TOKEN);
            mToken.put(token, objectMapper.writeValueAsString(cbsUserDto));
            mToken.setTtl(token, tokenProperties.getExpires(), TimeUnit.MINUTES);
            
            if (userId != null) {
            	// set authorization TTL
                IMap<Long, HashMap<String, String>> mAuth = hazelcastInstance.getMap(Const.DFT.AUTHORIZATION);
                mAuth.setTtl(userId, tokenProperties.getExpires(), TimeUnit.MINUTES);
                
                // set user token cache
                IMap<String, HazelcastJsonValue> mUser = hazelcastInstance.getMap(Const.DFT.USER_TOKEN);
                mUser.put(token, new HazelcastJsonValue(objectMapper.writeValueAsString(cbsUserDto)));
                mUser.setTtl(token, tokenProperties.getExpires(), TimeUnit.MINUTES);
            }
            
        } catch (Exception e) {
        	log.error("error, {}", e);
        }
    }
	
	/**
	 * Cache authorization
	 * 
	 * @param userId
	 * @param listAuth
	 * @param listRestApiReadable
	 */
	public void cacheAuthorization(long userId, List<MenuDto> listAuth, List<AmRestApi> listRestApiReadable, boolean isAppend) {
    	
        HashMap<String, String> authUser = new HashMap<>();

        listAuth.forEach(item -> {
            String[] apiPaths = StringUtils.split(item.getApiPath(), ",");
            if (apiPaths != null) {
                Arrays.stream(apiPaths).forEach(path -> authUser.put(path + "#" + RequestMethodUtil.getRightCode(RequestMethod.GET), RequestMethodUtil.getRightCode(RequestMethod.GET)));
            }

            String[] apiMains = StringUtils.split(item.getApiMain(), ",");
            if (apiMains != null) {
                Arrays.stream(apiMains).forEach(path -> authUser.put(path + "#" + item.getRightCode(), item.getRightCode()));
            }
        });

        listRestApiReadable.forEach(item -> {
            authUser.put(item.getPath() + "#" + RequestMethodUtil.getRightCode(RequestMethod.GET), RequestMethodUtil.getRightCode(RequestMethod.GET));
        });
        
        IMap<Long, HashMap<String, String>> mAuth = hazelcastInstance.getMap(Const.DFT.AUTHORIZATION);
        
        // append to exists cache
        if(mAuth.containsKey(userId) && isAppend){
        	HashMap<String, String> currentAuth = mAuth.get(userId);
        	authUser.putAll(currentAuth);
        }
        mAuth.put(userId, authUser);
        
        // set TTL
        mAuth.setTtl(userId, tokenProperties.getExpires(), TimeUnit.MINUTES);
    }
	
	/**
	 * Check quyen cua user duoc luu trong cache authorization
	 * @param userId
	 * @param requestPath
	 * @param requestMethod
	 * @return
	 */
	public boolean hasPermission(Long userId, String requestPath, RequestMethod requestMethod) {
		
		// get cache user
		IMap<Long, HashMap<String, String>> mAuth = hazelcastInstance.getMap(Const.DFT.AUTHORIZATION);
		HashMap<String, String> authUser = mAuth.get(userId);
		if (authUser == null) {
			return false;
		}
		
		return authUser.containsKey(requestPath + "#" + RequestMethodUtil.getRightCode(requestMethod));
	}
	
	/**
	 * Count current user session
	 * 
	 * @param userId
	 * @return
	 */
	public int countSession(long userId) {
		
		IMap<String, HazelcastJsonValue> mToken = hazelcastInstance.getMap(Const.DFT.USER_TOKEN);
		
        Collection<HazelcastJsonValue> results = mToken.values(Predicates.equal("id", userId));
        
        return results.size();
	}
}
