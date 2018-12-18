package team.balam.security.jwt;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Map;

public class JwtTranslator {
    private Key key;
    private Encoder<byte[], String> encoder;
    private Decoder<String, byte[]> decoder;

    public JwtTranslator(byte[] secretKey, boolean isUrlSafe) {
        key = Keys.hmacShaKeyFor(secretKey);

        if (isUrlSafe) {
            encoder = Encoders.BASE64URL;
            decoder = Decoders.BASE64URL;
        } else {
            encoder = Encoders.BASE64;
            decoder = Decoders.BASE64;
        }
    }

    public String generate(AuthToken authToken) {
        return Jwts.builder()
                .base64UrlEncodeWith(encoder)
                .signWith(key).setHeaderParam("role", authToken.getRole())
                .setClaims(authToken.getInfo())
                .setExpiration(authToken.getExpirationTime()).compact();
    }

    @SuppressWarnings("unchecked")
    public AuthToken parse(String jwtString) {
        Jwt jwt =  Jwts.parser().base64UrlDecodeWith(decoder).setSigningKey(key).parse(jwtString);

        return AuthToken.builder()
                .role((String) jwt.getHeader().get("role"))
                .info((Map<String, Object>) jwt.getBody()).build();
    }
}
