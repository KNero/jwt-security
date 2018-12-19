package team.balam.security.jwt.access;

import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@ToString
class AccessRole {
    private boolean isAllAccessible;
    private Set<String> roles = new HashSet<>();

    AccessRole addRole(String role) {
        roles.add(role);
        return this;
    }

    void allAccessible() {
        isAllAccessible = true;
    }

    boolean containsRole(String role) {
        return isAllAccessible || roles.contains(role);
    }
}
