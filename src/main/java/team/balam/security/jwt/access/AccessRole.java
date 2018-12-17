package team.balam.security.jwt.access;

import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@ToString
class AccessRole {
    private Set<String> roles = new HashSet<>();

    AccessRole addRole(String role) {
        roles.add(role);
        return this;
    }

    boolean containsRole(String role) {
        return roles.contains(role);
    }
}
