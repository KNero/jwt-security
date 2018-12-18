package team.balam.security.jwt;

import io.jsonwebtoken.JwtException;

public class AuthenticationException extends Exception {
    public AuthenticationException(JwtException e) {
        super(e);
    }
}
