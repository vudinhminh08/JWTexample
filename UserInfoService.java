package vn.mbf.cbs.auth.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import vn.mbf.cbs.auth.dto.MenuDto;
import vn.mbf.cbs.auth.entity.AmRestApi;

@Service
@AllArgsConstructor
@Slf4j
public class UserInfoService {
	
	private DataSource dataSource;
	private AmRestApiService amRestApiService;
	private CacheService cacheService;
	
    public List<MenuDto> getListModuleAuthorization(Long userId, String appCode) throws Exception {
    	
        //log.info("userId: {}, appCode: {}",userId,appCode);
        String strSQL = "" +
                "SELECT ao.object_id,\n" +
                "       ao.parent_id,\n" +
                "       ao.PATH,\n" +
                "       (SELECT listagg (ap.PATH,',') within group ( order by ap.PATH )\n" +
                "        FROM am_rest_api ap, am_api_object apo\n" +
                "        WHERE     ap.api_id = apo.api_id\n" +
                "          AND ap.status = 1\n" +
                "          AND nvl(apo.main_api, '0') <> '1'\n" +
                "          AND apo.object_id = ao.object_id) api_path,\n" +
                "       (SELECT listagg (ap.PATH,',') within group ( order by ap.PATH )\n" +
                "        FROM am_rest_api ap, am_api_object apo\n" +
                "        WHERE     ap.api_id = apo.api_id\n" +
                "          AND ap.status = 1\n" +
                "          AND apo.main_api = '1'\n" +
                "          AND apo.object_id = ao.object_id) api_main,\n" +
                "       aorg.right_code,\n" +
                "       MOD (MIN (2 * child_level + access_type), 2) access_type\n" +
                "FROM am_object ao,\n" +
                "     (SELECT auo.object_id,\n" +
                "             auo.right_code,\n" +
                "             auo.access_type,\n" +
                "             0   child_level\n" +
                "      FROM am_user_object auo, am_object_right aor\n" +
                "      WHERE     auo.object_id = aor.object_id\n" +
                "        AND auo.right_code = aor.right_code\n" +
                "\t    AND auo.user_id = ?\n" +
                "      UNION ALL\n" +
                "      SELECT aor2.object_id,\n" +
                "             aor2.right_code,\n" +
                "             aor2.access_type,\n" +
                "             1000 child_level\n" +
                "      FROM am_object_right aor2\n" +
                "      WHERE aor2.access_type > 0\n" +
                "      UNION ALL\n" +
                "      SELECT DISTINCT ago.object_id,\n" +
                "             ago.right_code,\n" +
                "             ago.access_type,\n" +
                "             ag.child_level\n" +
                "      FROM am_group_object ago,\n" +
                "           am_object_right aor3,\n" +
                "           (SELECT ag.GROUP_ID, LEVEL child_level\n" +
                "            FROM am_group ag\n" +
                "            WHERE NVL (status, 0) > 0\n" +
                "            START WITH ag.GROUP_ID IN (SELECT agu.GROUP_ID\n" +
                "                                       FROM am_group_user agu\n" +
                "                                       WHERE agu.user_id = ?)\n" +
                "            CONNECT BY PRIOR ag.parent_id = ag.GROUP_ID) ag\n" +
                "      WHERE ago.GROUP_ID = ag.GROUP_ID AND ago.object_id = aor3.object_id)\n" +
                "\t     aorg,\n" +
                "     (SELECT aao.object_id oid, aa.code\n" +
                "      FROM am_app_object aao, am_app aa\n" +
                "      WHERE aa.app_id = aao.app_id AND aa.status = '1') new_aa\n" +
                "WHERE     ao.object_id = aorg.object_id\n" +
                "  AND ao.object_id = new_aa.oid\n" +
                "  AND (? IS NULL OR new_aa.code = ?)\n" +
                "  AND NVL (ao.status, 0) > 0\n" +
                "GROUP BY ao.object_id,\n" +
                "         ao.parent_id,\n" +
                "         ao.PATH,\n" +
                "         aorg.right_code\n" +
                "HAVING MOD (MIN (2 * child_level + access_type), 2) > 0";

        //log.info("SQL: {}",strSQL);

        List<MenuDto> returnValue = new ArrayList<>();
        Map<Long, String> mapModuleId = new HashMap<>();
        
        PreparedStatement mStmt = null;
        ResultSet mRs = null;
        
        try (Connection mConnection = dataSource.getConnection();) {
        	
        	mStmt = mConnection.prepareStatement(strSQL);
            mStmt.setLong(1, userId);
            mStmt.setLong(2, userId);
            mStmt.setString(3, appCode);
            mStmt.setString(4, appCode);
            mRs = mStmt.executeQuery();

            while (mRs.next()) {
                //Add to map
                mapModuleId.put(mRs.getLong("object_id"), null);

                //Add to return object
                MenuDto menu = new MenuDto();
                menu.setObjectId(mRs.getLong("object_id"));
                menu.setParentId(mRs.getLong("parent_id"));
                menu.setPath(mRs.getString("path"));
                menu.setApiPath(mRs.getString("api_path"));
                menu.setApiMain(mRs.getString("api_main"));
                menu.setRightCode(mRs.getString("right_code"));
                menu.setAccessType(mRs.getString("access_type"));
                returnValue.add(menu);
            }
            
            for (int i = 0; i < returnValue.size(); i++) {
                if (returnValue.get(i).getParentId() != 0 && !mapModuleId.containsKey(returnValue.get(i).getParentId())) {
                    returnValue.remove(i--);
                }
            }
        } catch (Exception e) {
        	log.error("error", e);
        } finally {
        	if (mStmt != null) {
        		mStmt.close();
        	}
        	
        	if (mRs != null) {
        		mRs.close();
        	}
        }
        
        List<AmRestApi> listRestApiReadable = amRestApiService.findByReadableAndStatus("1", "1");
        
        // store in the cache
        cacheService.cacheAuthorization(userId, returnValue, listRestApiReadable, false);
        
        return returnValue;
    }
}
