package team.balam.security.jwt.access;

public class AccessInfoExistsException extends Exception {
    AccessInfoExistsException(String info) {
        super(info);
    }
}