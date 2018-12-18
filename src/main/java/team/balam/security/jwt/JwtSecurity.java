package team.balam.security.jwt;

import io.jsonwebtoken.JwtException;
import team.balam.security.jwt.access.AccessInfoExistsException;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.RoleAdministrator;

import java.util.UUID;
import java.util.function.Function;

public class JwtSecurity<T> {
    private JwtTranslator jwtTranslator;
    private Function<T, AuthToken> authTokenConverter;
    private ObjectConverter<T> objectConverter;

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
        return jwtTranslator.generate(authToken);
    }

    @SuppressWarnings("unchecked")
    public void authenticate(String jwtString, AccessTarget accessTarget) throws AuthenticationException, AuthorizationException {
        try {
            if (jwtString == null || jwtString.isEmpty()) {
                roleAdministrator.checkAuthorization(accessTarget, null);
            } else {
                AuthToken authToken = jwtTranslator.parse(jwtString);

                roleAdministrator.checkAuthorization(accessTarget, authToken.getRole());

                authResultRepository.set(objectConverter.convert(authToken));
            }
        } catch (JwtException e) {
            throw new AuthenticationException(e);
        }
    }

    public static class Builder<T> {
        private JwtSecurity<T> jwtSecurity = new JwtSecurity<>();
        private String[] packages;

        private byte[] secretKey;
        private boolean isUrlSafe;

        public Builder<T> setSecretKey(String secretKey) {
            if (secretKey == null || secretKey.isEmpty()) {
                throw new InitializeException("secretKey is empty");
            }

            this.secretKey = secretKey.getBytes();
            return this;
        }

        public Builder<T> setAuthTokenConverter(Function<T, AuthToken> authTokenConverter) {
            jwtSecurity.authTokenConverter = authTokenConverter;
            return this;
        }

        public Builder<T> setObjectConverter(ObjectConverter<T> objectConverter) {
            jwtSecurity.objectConverter = objectConverter;
            return this;
        }

        public Builder<T> setPackages(String... packages) {
            this.packages = packages;
            return this;
        }

        public Builder<T> setUrlSafe(boolean isUrlSafe) {
            this.isUrlSafe = isUrlSafe;
            return this;
        }

        public Builder<T> addAdminRole(String adminRole) {
            jwtSecurity.roleAdministrator.addAdminRole(adminRole);
            return this;
        }

        public JwtSecurity<T> build() throws AccessInfoExistsException {
            if (this.secretKey == null) {
                throw new InitializeException("secretKey is empty");
            } else if (jwtSecurity.authTokenConverter == null) {
                throw new InitializeException("authTokenConverter is null");
            } else if (jwtSecurity.objectConverter == null) {
                throw new InitializeException("objectConverter is null");
            } else if (this.packages == null || this.packages.length == 0) {
                throw new InitializeException("packages is null");
            }

            jwtSecurity.jwtTranslator = new JwtTranslator(this.secretKey, this.isUrlSafe);
            jwtSecurity.roleAdministrator.init(packages);

            return jwtSecurity;
        }
    }
}
