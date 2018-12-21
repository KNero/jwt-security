package team.balam.security.jwt.access;

public class AccessInfoExistsException extends RuntimeException {
    AccessInfoExistsException(String info) {
        super(info);
    }
}