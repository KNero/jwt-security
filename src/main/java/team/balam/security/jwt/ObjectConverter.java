package team.balam.security.jwt;

@FunctionalInterface
public interface ObjectConverter<T> {
    T convert(AuthToken authToken) throws AuthenticationException;
}
