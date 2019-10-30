package team.balam.security.jwt;

import java.util.function.Function;

/**
 * 헤더 구조가 아래와 같이 전달되어야 한다.
 * Authorization: Bearer token
 */
public class DefaultTokenParser implements Function<String, String> {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer";
    private static final String TOKEN_SEPARATOR = " ";

    @Override
    public String apply(String authorization) {
        if (authorization != null) {
            String[] authInfo = authorization.split(TOKEN_SEPARATOR);
            if (authInfo.length == 2 && TOKEN_PREFIX.equals(authInfo[0])) {
                return authInfo[1];
            }
        }

        return null;
    }
}
