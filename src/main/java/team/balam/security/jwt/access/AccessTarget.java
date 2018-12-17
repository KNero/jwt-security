package team.balam.security.jwt.access;

import lombok.ToString;

@ToString
public class AccessTarget {
    private String path;
    private Class<?> type;
    private String method;

    public AccessTarget(String path) {
        this.path = path;
    }

    public AccessTarget(Class<?> type, String method) {
        this.type = type;
        this.method = method;
    }

    @Override
    public int hashCode() {
        if (path != null) {
            return path.hashCode();
        } else {
            return type.hashCode() + method.hashCode();
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof AccessTarget) {
            AccessTarget other = (AccessTarget) obj;

            if (path != null && other.path.equals(path)) {
                return true;
            }

            return other.type.equals(type) && other.method.equals(method);
        }

        return false;
    }
}
