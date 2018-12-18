package team.balam.security.jwt;

import io.jsonwebtoken.JwtException;

public class AuthenticationException extends Exception {
    AuthenticationException(JwtException e) {
        super(e);
    }

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException() {

    }
}
