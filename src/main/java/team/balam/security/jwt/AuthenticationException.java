package team.balam.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

public class AuthenticationException extends Exception {
    private boolean isExpired;

    AuthenticationException(JwtException e) {
        super(e);
        isExpired = e instanceof ExpiredJwtException;
    }

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException() {

    }

    public boolean isExpired() {
        return isExpired;
    }
}
