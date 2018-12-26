package team.balam.security.jwt;

import org.junit.Assert;
import org.junit.Test;
import team.balam.security.jwt.access.AccessInfoExistsException;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.RestAccess;

import java.util.HashMap;
import java.util.Map;

public class WildcardTest {
    @RestAccess(uri = "/test/*/1234", method = "get", role = {"rest1", "rest3"})
    public void rest() {
    }

    @Test
    public void test_wildcard() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = JwtSecurityTest.createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();
        data.put("role", "rest1");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/test/wildcard-1/1234", "GET"));

        data.put("role", "rest3");
        jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/test/wildcard-2/1234", "GET"));

        try {
            data.put("role", "rest2");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate(jwt, new AccessTarget("/test/wildcard-3/1234", "GET"));
            Assert.fail();
        } catch (AuthorizationException e) {
        }
    }
}
