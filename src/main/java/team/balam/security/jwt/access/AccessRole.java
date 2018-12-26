package team.balam.security.jwt.access;

import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@ToString
class AccessRole {
    private Set<String> roles = new HashSet<>();
    private boolean isAllRoleAccessible;
    private boolean isAllRequestAccessible;

    AccessRole addRole(String role) {
        roles.add(role);
        return this;
    }

    public void allRoleAccessible() {
        isAllRoleAccessible = true;
    }

    public void allRequestAccessible() {
        isAllRequestAccessible = true;
    }

    boolean containsRole(String role) {
        if (isAllRequestAccessible) {
            return true;
        }

        if (role == null || role.isEmpty()) {
            return false;
        }

        return isAllRoleAccessible || roles.contains(role);
    }
}
