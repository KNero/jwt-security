package team.balam.security.jwt;

import org.junit.Assert;
import org.junit.Test;
import team.balam.security.jwt.access.AccessInfoExistsException;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.RestAccess;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class WildcardTest {
    @RestAccess(uri = "/test/*/1234", method = "get", role = {"rest1", "rest3"})
    public void rest() {
    }

    @RestAccess(uri = "/api/branch/lecture/*", method = "get", role = {"rest1", "rest2"})
    public void rest2() {
    }

    @RestAccess(uri = "/api/branch/lecture/progress", method = "get", role = {"rest3", "rest4"})
    public void rest3() {
    }

    @Test
    public void test_wildcard() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = JwtSecurityTest.createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();
        data.put("role", "rest1");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/test/wildcard-1/1234", "GET"));

        data.put("role", "rest3");
        jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/test/wildcard-2/1234", "GET"));

        try {
            data.put("role", "rest2");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/test/wildcard-3/1234", "GET"));
            Assert.fail();
        } catch (AuthorizationException e) {
            // rest2 는 접근 불가
        }
    }

    @Test
    public void test_wildcard1() throws Exception {
        JwtSecurity<Map<String, Object>> jwtSecurity = JwtSecurityTest.createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();

        try {
            data.put("role", "rest2");
            String jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/api/branch/lecture/progress", "GET"));
        } catch (AuthorizationException e) {
            // rest2 는 접근 불가
        }

        data.put("role", "rest2");
        String jwt = jwtSecurity.generateToken(data);
        // rest2 가능
        jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/api/branch/lecture/wildcard", "GET"));

        data.put("role", "rest4");
        jwt = jwtSecurity.generateToken(data);
        // rest1, rest2 가능
        jwtSecurity.authenticate("Bearer " + jwt, new AccessTarget("/api/branch/lecture/progress", "GET"));
    }
}
