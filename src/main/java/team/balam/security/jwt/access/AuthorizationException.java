package team.balam.security.jwt.access;

public class AuthorizationException extends Exception {
    AuthorizationException(String message) {
        super(message);
    }
}
