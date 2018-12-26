package team.balam.security.jwt;

import org.junit.Assert;
import org.junit.Test;
import team.balam.security.jwt.access.*;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtSecurityTest {
    @PathAccess(path = "/path/access1", role = "ROLE1")
    public void pathAccess1() {
    }

    @PathAccess(path = "/path/access2", role = {"ROLE2", "ROLE3"})
    public void pathAccess2() {
    }

    @MethodAccess(role = "METHOD1")
    public void methodAccess1() {
    }

    @RestAccess(uri = "/test", method = "get", role = {"rest1", "rest2"})
    public void testGet() {
    }

    @MethodAccess(allRole = true)
    public void methodAccess2() {
    }

    @MethodAccess(allRequest = true)
    public void methodAccess3() {
    }

    @Test
    public void test_createSecretKey() {
        Assert.assertEquals(32, JwtSecurity.create32BitesSecretKey().length());
        Assert.assertEquals(48, JwtSecurity.create48BitesSecretKey().length());
        Assert.assertEquals(64, JwtSecurity.create64BitesSecretKey().length());
    }

    @Test
    public void test_setSecretKey() {
        new JwtSecurity.Builder().setSecretKey(JwtSecurity.create32BitesSecretKey());
        new JwtSecurity.Builder().setSecretKey(JwtSecurity.create48BitesSecretKey());
        new JwtSecurity.Builder().setSecretKey(JwtSecurity.create64BitesSecretKey());
    }

    @Test
    public void test_pathAuthentication() throws AuthenticationException, AuthorizationException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);
        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME_A");
        data.put("email", "test@test.com");

        data.put("role", "ROLE1");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/path/access1"));

        Map<String, Object> jwtData = jwtSecurity.getAuthenticationInfo();
        Assert.assertEquals(data.get("name"), jwtData.get("name"));
        Assert.assertEquals(data.get("email"), jwtData.get("email"));

        try {
            data.put("role", "ROLE2");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate(jwt, new AccessTarget("/path/access1"));
            Assert.fail(); // ROLE2 는 접근할 수 없는 롤이기 때문에 AuthorizationException 발생하여 이 부분이 실행되지 않음.
        } catch (AuthorizationException e) {
        }
    }

    @Test
    public void test_methodAuthentication() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);
        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME_A");
        data.put("email", "test@test.com");

        data.put("role", "METHOD1");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess1"));

        try {
            data.put("role", "METHOD2");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess1"));
            Assert.fail(); // METHOD2 는 접근할 수 없는 롤이기 때문에 AuthorizationException 발생하여 이 부분이 실행되지 않음.
        } catch (AuthorizationException e) {
        }
    }

    @Test
    public void test_multiRole() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();

        data.put("role", "ROLE2");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/path/access2"));

        data.put("role", "ROLE3");
        jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/path/access2"));

        try {
            data.put("role", "ROLE1");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate(jwt, new AccessTarget("/path/access2"));

            Assert.fail();
        } catch (AuthorizationException e) {
            //expected
        }
    }

    @Test
    public void test_restMultiRole() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();
        data.put("name", "1");
        data.put("email", "test@2");

        data.put("role", "rest1");
        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/test", "GET"));

        Map<String, Object> jwtData = jwtSecurity.getAuthenticationInfo();
        Assert.assertEquals(data.get("name"), jwtData.get("name"));
        Assert.assertEquals(data.get("email"), jwtData.get("email"));

        data.put("role", "rest2");
        jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget("/test", "GET"));

        try {
            data.put("role", "rest3");
            jwt = jwtSecurity.generateToken(data);
            jwtSecurity.authenticate(jwt, new AccessTarget("/test", "GET"));
            Assert.fail(); // rest3 롤이 없기 때문에 AuthorizationException 발생
        } catch (AuthorizationException e) {
        }
    }

    @Test
    public void test_adminRole() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME_A");
        data.put("email", "test@test.com");
        data.put("role", "ADMIN");

        String jwt = jwtSecurity.generateToken(data);

        jwtSecurity.authenticate(jwt, new AccessTarget("/path/access1"));

        Map<String, Object> jwtData = jwtSecurity.getAuthenticationInfo();
        Assert.assertEquals(data.get("name"), jwtData.get("name"));
        Assert.assertEquals(data.get("email"), jwtData.get("email"));
    }

    @Test(expected = AuthorizationException.class)
    public void test_failAuthentication1() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(false);

        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME_A");
        data.put("email", "test@test.com");
        data.put("role", "ROLE2");

        String jwt = jwtSecurity.generateToken(data);

        jwtSecurity.authenticate(jwt, new AccessTarget("/path/access1"));

        Map<String, Object> jwtData = jwtSecurity.getAuthenticationInfo();
        Assert.assertEquals(data.get("name"), jwtData.get("name"));
        Assert.assertEquals(data.get("email"), jwtData.get("email"));
    }

    @Test(expected = AuthorizationException.class)
    public void test_failAuthentication2() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(false);

        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME_A");
        data.put("email", "test@test.com");
        data.put("role", "ROLE1");

        String jwt = jwtSecurity.generateToken(data);

        jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess1"));

        Map<String, Object> jwtData = jwtSecurity.getAuthenticationInfo();
        Assert.assertEquals(data.get("name"), jwtData.get("name"));
        Assert.assertEquals(data.get("email"), jwtData.get("email"));
    }

    @Test
    public void test_urlSafe() throws AccessInfoExistsException {
        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME A");
        data.put("email", "test@test.c");
        data.put("role", "ROLE 1");

        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(false);
        String jwt = jwtSecurity.generateToken(data);
        System.out.println(jwt);
        Assert.assertTrue(jwt.contains("="));
    }

    @Test(expected = AuthenticationException.class)
    public void test_hackHeader() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        Map<String, Object> data = new HashMap<>();
        data.put("name", "NAME A");
        data.put("email", "test@test.c");
        data.put("role", "METHOD1");

        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(false);
        String jwt = jwtSecurity.generateToken(data);

        jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess1"));

        String header = "{\"role\":\"METHOD 2222\",\"alg\":\"HS256\"}";
        jwt = Base64.getEncoder().encodeToString(header.getBytes()) + "." + jwt.split("\\.")[1] + "." + jwt.split("\\.")[2];
        jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess1"));
    }

    @Test
    public void test_allRequest() throws AuthenticationException, AuthorizationException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);
        // jwt 가 null 이라도 allRequest 가 활성화 되었기 때문에 접근 가능하다
        jwtSecurity.authenticate(null, new AccessTarget(JwtSecurityTest.class, "methodAccess3"));
    }

    @Test
    public void test_allRole() throws AuthenticationException, AuthorizationException, AccessInfoExistsException {
        JwtSecurity<Map<String, Object>> jwtSecurity = createJwtSecurity(true);

        Map<String, Object> data = new HashMap<>();
        data.put("role", "ROLE2");

        String jwt = jwtSecurity.generateToken(data);
        jwtSecurity.authenticate(jwt, new AccessTarget(JwtSecurityTest.class, "methodAccess2"));
    }

     public static JwtSecurity<Map<String, Object>> createJwtSecurity(boolean isUrlSafe) throws AccessInfoExistsException {
        return new JwtSecurity.Builder<Map<String, Object>>()
                .setPackages("team.balam.security.jwt")
                .setSecretKey(JwtSecurity.create32BitesSecretKey())
                .addAdminRole("ADMIN")
                .setAuthTokenConverter(data -> {
                    Date date = new Date(System.currentTimeMillis() + 10000);
                    return AuthToken.builder()
                            .info(data)
                            .role((String) data.get("role"))
                            .expirationTime(date)
                            .build();
                })
                .setObjectConverter(AuthToken::getInfo)
                .setUrlSafe(isUrlSafe).build();
    }
}
