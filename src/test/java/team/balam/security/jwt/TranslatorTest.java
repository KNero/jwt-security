package team.balam.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class TranslatorTest {
    @Test
    public void AllInfoContainTest() {
        Map<String, Object> data = new HashMap<>();
        data.put("a", "A");

        AuthToken authToken = AuthToken.builder()
                .role("role1")
                .info(data)
                .subject("subject")
                .audience("audience")
                .issuer("issuer")
                .expirationTime(new Date(System.currentTimeMillis() + 100000))
                .notBefore(new Date())
                .jwtId(UUID.randomUUID().toString())
                .build();

        JwtTranslator translator = new JwtTranslator(JwtSecurity.create48BitesSecretKey().getBytes(), true);
        String token = translator.generate(authToken);

        AuthToken parseToken = translator.parse(token);

        Assert.assertEquals(authToken.getRole(), parseToken.getRole());
        Assert.assertEquals(authToken.getInfo().get("a"), parseToken.getInfo().get("a"));
        Assert.assertEquals(authToken.getSubject(), parseToken.getSubject());
        Assert.assertEquals(authToken.getAudience(), parseToken.getAudience());
        Assert.assertEquals(authToken.getIssuer(), parseToken.getIssuer());
        Assert.assertEquals(authToken.getExpirationTime().getTime() / 1000 * 1000, parseToken.getExpirationTime().getTime()); // 초 단위로 검사. ms 사용 안함
        Assert.assertEquals(authToken.getNotBefore().getTime() / 1000 * 1000, parseToken.getNotBefore().getTime()); // 초 단위로 검사. ms 사용 안함
        Assert.assertEquals(authToken.getJwtId(), parseToken.getJwtId());
        Assert.assertNotNull(parseToken.getIssuedAt());
    }

    @Test
    public void test() {
        Map<String, Object> data = new HashMap<>();
        data.put("a", "A");

        AuthToken authToken = AuthToken.builder().role("role1").info(data).build();

        JwtTranslator translator = new JwtTranslator(JwtSecurity.create48BitesSecretKey().getBytes(), true);
        String token = translator.generate(authToken);

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
