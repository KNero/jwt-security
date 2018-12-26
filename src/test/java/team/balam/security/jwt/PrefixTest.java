package team.balam.security.jwt;

import org.junit.Assert;
import org.junit.Test;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.RestAccess;

import java.util.Date;
import java.util.HashMap;

public class PrefixTest {
    @RestAccess(uri = "/prefix1/test1", method = "get", role = "user2")
    public void test1() {
    }

    @RestAccess(uri = "/prefix1/test2", method = "get", role = "user1")
    public void test2() {
    }

    @Test
    public void test() throws AuthenticationException, AuthorizationException {
        JwtSecurity<String> jwtSecurity = new JwtSecurity.Builder<String>()
                .setPackages("team.balam.security")
                .setSecretKey(JwtSecurity.create32BitesSecretKey())
                .addAdminRole("ADMIN")
                .addPrefix("/prefix1")
                .setAuthTokenConverter(data -> {
                    Date date = new Date(System.currentTimeMillis() + 10000);
                    return AuthToken.builder()
                            .info(new HashMap<>())
                            .role(data)
                            .expirationTime(date)
                            .build();
                })
                .setObjectConverter(AuthToken::getRole)
                .build();

        String jwt = jwtSecurity.generateToken("user1");

        try {
            jwtSecurity.authenticate(jwt, new AccessTarget("/prefix1/test1", "get"));
            Assert.fail();
        } catch (AuthenticationException | AuthorizationException e) {
        }

        jwtSecurity.authenticate(jwt, new AccessTarget("/prefix1/test2", "get"));

        try {
            // jwt 가 없을 경우 통과할 수 없다.
            jwtSecurity.authenticate(null, new AccessTarget("/prefix1/test3", "get"));
            Assert.fail();
        } catch (AuthenticationException | AuthorizationException e) {
        }
    }
}
