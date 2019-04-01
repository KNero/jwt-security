package team.balam.security.jwt;

import team.balam.security.jwt.access.AccessTarget;
import team.balam.security.jwt.access.AuthorizationException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;


public abstract class JwtFilter<T> implements Filter {
    protected JwtSecurity<T> jwtSecurity;

    @Override
    public final void init(FilterConfig filterConfig) throws ServletException {
        jwtSecurity = build(new JwtSecurity.Builder<>(), filterConfig);
    }

    protected abstract JwtSecurity<T> build(JwtSecurity.Builder<T> builder, FilterConfig filterConfig) throws ServletException;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String uri = httpServletRequest.getRequestURI();
        String method = httpServletRequest.getMethod();
        String jwt = null;

        String authorization = httpServletRequest.getHeader("Authorization");
        if (authorization != null) {
            String[] authInfo = authorization.split(" ");
            if (authInfo.length == 2 && "Bearer".equals(authInfo[0])) {
                jwt = authInfo[1];
            }
        }

        try {
            jwtSecurity.authenticate(jwt, new AccessTarget(uri, method));
        } catch (AuthenticationException e) { // AuthenticationException 인증 실패
            onFailAuthentication(request, response, e);
        } catch (AuthorizationException e) { // AuthorizationException 접근 권한이 없을 경우
            onFailAuthorization(request, response, e);
        }

        chain.doFilter(request, response);
    }

    /**
     * 인증실패
     */
    protected void onFailAuthentication(ServletRequest request, ServletResponse response, AuthenticationException e) throws ServletException {
        throw new ServletException(e);
    }

    /**
     * 접근실패
     */
    protected void onFailAuthorization(ServletRequest request, ServletResponse response, AuthorizationException e) throws ServletException {
        throw new ServletException(e);
    }

    @Override
    public void destroy() {

    }
}
