package team.balam.security.jwt;

import io.jsonwebtoken.JwtException;
import team.balam.security.jwt.access.AccessInfoExistsException;
import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;
import team.balam.security.jwt.access.AccessController;

import java.util.UUID;
import java.util.function.Function;

public class JwtSecurity<T> {
    private JwtTranslator jwtTranslator;
    private Function<T, AuthToken> authTokenConverter;
    private ObjectConverter<T> objectConverter;

    private AccessController accessController = new AccessController();

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
                accessController.checkAuthorization(accessTarget, null);
            } else {
                AuthToken authToken = jwtTranslator.parse(jwtString);
                authResultRepository.set(objectConverter.convert(authToken));

                accessController.checkAuthorization(accessTarget, authToken.getRole());
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
            jwtSecurity.accessController.addAdminRole(adminRole);
            return this;
        }

        /**
         * 검사하지 않고 통과시킬 uri 의 prefix 를 등록한다.
         */
        public Builder<T> addIgnorePrefix(String prefix) {
            jwtSecurity.accessController.addIgnorePrefix(prefix);
            return this;
        }

        /**
         * PathAccess 의 path 와 RestAccess 의 uri 에 prefix 부여하여 해당 요청을 모두 검사한다.
         */
        public Builder<T> addPrefix(String prefix) {
            jwtSecurity.accessController.addPrefix(prefix);
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
            jwtSecurity.accessController.init(packages);

            return jwtSecurity;
        }
    }
}
