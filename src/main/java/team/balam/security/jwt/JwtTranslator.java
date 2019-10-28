package team.balam.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

class JwtTranslator {
    private JwtBuilder jwtBuilder;
    private JwtParser jwtParser;

    JwtTranslator(byte[] secretKey, boolean isUrlSafe) {
        Key key = Keys.hmacShaKeyFor(secretKey);
        Encoder<byte[], String> encoder;
        Decoder<String, byte[]> decoder;

        if (isUrlSafe) {
            encoder = Encoders.BASE64URL;
            decoder = Decoders.BASE64URL;
        } else {
            encoder = Encoders.BASE64;
            decoder = Decoders.BASE64;
        }

        jwtBuilder = Jwts.builder().base64UrlEncodeWith(encoder).signWith(key);
        jwtParser = Jwts.parser().base64UrlDecodeWith(decoder).setSigningKey(key);
    }

    String generate(AuthToken authToken) {
        Objects.requireNonNull(authToken, "authToken is null.");

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("info", authToken.getInfo());

        return jwtBuilder
                .setHeaderParam("typ", "jwt")
                .setHeaderParam("role", authToken.getRole())
                .setClaims(claims)
                .setSubject(authToken.getSubject())
                .setAudience(authToken.getAudience())
                .setIssuer(authToken.getIssuer())
                .setIssuedAt(new Date()) // iat
                .setExpiration(authToken.getExpirationTime())
                .setId(authToken.getJwtId())
                .setNotBefore(authToken.getNotBefore())
                .compact();
    }

    @SuppressWarnings("unchecked")
    AuthToken parse(String jwtString) {
        Jwt jwt =  jwtParser.parse(jwtString);
        String role = (String) jwt.getHeader().get("role");
        Map<String, Object> claims = (Map<String, Object>) jwt.getBody();

        AuthToken.AuthTokenBuilder builder = AuthToken.builder()
                .role(role)
                .info((Map<String, Object>) claims.get("info"))
                .subject((String) claims.get(Claims.SUBJECT))
                .audience((String) claims.get(Claims.AUDIENCE))
                .issuer((String) claims.get(Claims.ISSUER))
                .jwtId((String) claims.get(Claims.ID));

        Object expiration = claims.get(Claims.EXPIRATION);
        if (expiration != null) {
            builder.expirationTime(new Date(Long.parseLong(expiration.toString()) * 1000)); // second to ms
        }

        Object issuedAt = claims.get(Claims.ISSUED_AT);
        if (issuedAt != null) {
            builder.issuedAt(new Date(Long.parseLong(issuedAt.toString()) * 1000));
        }

        Object notBefore = claims.get(Claims.NOT_BEFORE);
        if (notBefore != null) {
            builder.notBefore(new Date(Long.parseLong(notBefore.toString()) * 1000));
        }

        return builder.build();
    }
}
