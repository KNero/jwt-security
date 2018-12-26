package team.balam.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TranslatorTest {
    @Test
    public void test() {
        Map<String, Object> data = new HashMap<>();
        data.put("a", "A");

        AuthToken authToken = AuthToken.builder().role("role1").info(data).build();

        JwtTranslator translator = new JwtTranslator(JwtSecurity.create48BitesSecretKey().getBytes(), true);
        String token = translator.generate(authToken);
        System.out.println(token);

        AuthToken parseToken = translator.parse(token);

        Assert.assertEquals(authToken.getRole(), parseToken.getRole());
        Assert.assertEquals(authToken.getInfo().get("a"), parseToken.getInfo().get("a"));
    }

    @Test(expected = ExpiredJwtException.class)
    public void test_expiration() throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("a", "A");

        AuthToken authToken = AuthToken.builder().role("role1")
                .info(data)
                .expirationTime(new Date(System.currentTimeMillis() + 1000)).build();

        JwtTranslator translator = new JwtTranslator(JwtSecurity.create48BitesSecretKey().getBytes(), true);
        String token = translator.generate(authToken);

        Thread.sleep(2000);

        translator.parse(token);
    }
}
