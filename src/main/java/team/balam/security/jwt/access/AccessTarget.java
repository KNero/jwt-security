package team.balam.security.jwt.access;

public class AccessTarget {
    private String path;

    private Class<?> type;
    private String method;

    private String httpMethod;
    private RestUri httpUri;

    public AccessTarget(String path) {
        this.path = path;
    }

    public AccessTarget(Class<?> type, String method) {
        this.type = type;
        this.method = method;
    }

    public AccessTarget(String httpUri, String httpMethod) {
        this.httpMethod = httpMethod;
        this.httpUri = new RestUri(httpUri);
    }

    @Override
    public int hashCode() {
        if (path != null) {
            return path.hashCode();
        } else if (type != null && method != null) {
            return type.hashCode() + method.hashCode();
        } else if(httpUri != null && httpMethod != null) {
            return httpMethod.toLowerCase().hashCode();
        } else {
            return -1;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof AccessTarget) {
            AccessTarget other = (AccessTarget) obj;

            if (this.path != null && this.path.equals(other.path)) {
                return true;
            }

            if (this.type != null && this.method != null &&
                    this.type.equals(other.type) && this.method.equals(other.method)) {
                return true;
            }

            if (this.httpUri != null && this.httpMethod != null) {
                return this.httpUri.equals(other.httpUri) && this.httpMethod.equalsIgnoreCase(other.httpMethod);
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
