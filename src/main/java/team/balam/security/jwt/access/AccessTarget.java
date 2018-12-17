package team.balam.security.jwt.access;

import lombok.ToString;

public class AccessTarget {
    private String path;

    private Class<?> type;
    private String method;

    private String httpMethod;
    private String httpUri;

    public AccessTarget(String path) {
        this.path = path;
    }

    public AccessTarget(Class<?> type, String method) {
        this.type = type;
        this.method = method;
    }

    public AccessTarget(String httpUri, String httpMethod) {
        this.httpMethod = httpMethod;
        this.httpUri = httpUri;
    }

    @Override
    public int hashCode() {
        if (path != null) {
            return path.hashCode();
        } else if (type != null && method != null) {
            return type.hashCode() + method.hashCode();
        } else if(httpUri != null && httpMethod != null) {
            return httpMethod.toLowerCase().hashCode() + httpUri.hashCode();
        } else {
            return -1;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof AccessTarget) {
            AccessTarget other = (AccessTarget) obj;

            if (this.path != null && other.path != null &&
                    this.path.toLowerCase().equals(other.path.toLowerCase())) {
                return true;
            }

            if (this.type != null && other.type != null && this.method != null && other.method != null) {
                if (this.type.equals(other.type) && this.method.toLowerCase().equals(other.method.toLowerCase())) {
                    return true;
                }
            }

            if (this.httpUri != null && this.httpMethod != null && other.httpUri != null && other.httpMethod != null) {
                return this.httpUri.equals(other.httpUri) &&
                        this.httpMethod.toLowerCase().equals(other.httpMethod.toLowerCase());
            }
        }

        return false;
    }

    @Override
    public String toString() {
        if (path != null) {
            return "AccessTarget{path: " + path + "}";
        } else if (httpUri != null && httpMethod != null) {
            return "AccessTarget{httpUri: " + httpUri + ", httpMethod: " + httpMethod + "}";
        } else if (type != null && method != null) {
            return "AccessTarget{class: " + type + ", method: " + method + "}";
        } else {
            return "AccessTarget{path: " + path +
                    ", class: " + type +
                    ", method: " + method +
                    ", httpUri: " + httpUri +
                    ", httpMethod: " + httpMethod + "}";
        }
    }
}
