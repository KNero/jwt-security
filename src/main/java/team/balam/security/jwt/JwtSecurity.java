package team.balam.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import team.balam.security.jwt.access.AccessInfoExistsException;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.RoleAdministrator;

import java.security.Key;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

public class JwtSecurity<T> {
    private Key secretKey;
    private Function<T, AuthToken> authTokenConverter;
    private Function<AuthToken, T> objectConverter;
    private boolean isUrlSafe;

    private RoleAdministrator roleAdministrator = new RoleAdministrator();

    private ThreadLocal<T> authResultRepository = new ThreadLocal<>();

    private JwtSecurity() {
    }

    public static String create64BitesSecretKey() {
        return createSecretKey(64);
    }

    public static String create48BitesSecretKey() {
        return createSecretKey(48);
    }

    public static String create32BitesSecretKey() {
        return createSecretKey(32);
    }

    private static String createSecretKey(int length) {
        String key1 = UUID.randomUUID().toString().replaceAll("-", "");
        String key2 = UUID.randomUUID().toString().replaceAll("-", "");
        return (key1 + key2).substring(0, length);
    }

    public T getAuthenticationInfo() {
        return authResultRepository.get();
    }

    public String generateToken(T t) {
        AuthToken authToken = authTokenConverter.apply(t);

        JwtBuilder jwtBuilder = Jwts.builder()
                .signWith(secretKey)
                .setClaims(authToken.getInfo());

        if (!isUrlSafe) {
            jwtBuilder.base64UrlEncodeWith(Encoders.BASE64);
        }

        if (authToken.getRole() != null) {
            jwtBuilder.setHeaderParam("role", authToken.getRole());
        }

        if (authToken.getExpirationTime() != null) {
            jwtBuilder.setExpiration(authToken.getExpirationTime());
        }

        return jwtBuilder.compact();
    }

    @SuppressWarnings("unchecked")
    public void authenticate(String jwtString, AccessTarget accessTarget) throws AuthenticationException, AuthorizationException {
        try {
            JwtParser jwtParser = Jwts.parser().setSigningKey(secretKey);
            if (!isUrlSafe) {
                jwtParser.base64UrlDecodeWith(Decoders.BASE64);
            }

            Jwt jwt = jwtParser.parse(jwtString);

            AuthToken authToken = AuthToken.builder()
                    .role((String) jwt.getHeader().get("role"))
                    .info((Map<String, Object>) jwt.getBody()).build();

            roleAdministrator.checkAuthorization(accessTarget, authToken.getRole());

            authResultRepository.set(objectConverter.apply(authToken));
        } catch (JwtException e) {
            throw new AuthenticationException(e);
        }
    }

    public static class Builder<T> {
        private JwtSecurity<T> jwtSecurity = new JwtSecurity<>();
        private String[] packages;

        public Builder<T> setSecretKey(String secretKey) {
            if (secretKey == null || secretKey.isEmpty()) {
                throw new InitializeException("secretKey is empty");
            }

            jwtSecurity.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
            return this;
        }

        public Builder<T> setAuthTokenConverter(Function<T, AuthToken> authTokenConverter) {
            jwtSecurity.authTokenConverter = authTokenConverter;
            return this;
        }

        public Builder<T> setObjectConverter(Function<AuthToken, T> objectConverter) {
            jwtSecurity.objectConverter = objectConverter;
            return this;
        }

        public Builder<T> setPackages(String... packages) {
            this.packages = packages;
            return this;
        }

        public Builder<T> setUrlSafe(boolean isUrlSafe) {
            jwtSecurity.isUrlSafe = isUrlSafe;
            return this;
        }

        public JwtSecurity<T> build() throws AccessInfoExistsException {
            if (jwtSecurity.secretKey == null) {
                throw new InitializeException("secretKey is empty");
            } else if (jwtSecurity.authTokenConverter == null) {
                throw new InitializeException("authTokenConverter is null");
            } else if (jwtSecurity.objectConverter == null) {
                throw new InitializeException("objectConverter is null");
            } else if (this.packages == null || this.packages.length == 0) {
                throw new InitializeException("packages is null");
            }

            jwtSecurity.roleAdministrator.init(packages);

            return jwtSecurity;
        }
    }
}
