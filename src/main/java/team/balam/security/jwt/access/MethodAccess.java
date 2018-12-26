package team.balam.security.jwt.access;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface MethodAccess {
    String[] role() default "";

    /**
     * 인증 받은 모든 사용자가 이용할 수 있는지 여부
     */
    boolean allRole() default false;

    /**
     * 모든 요청이 이용할 수 있는지 여부
     */
    boolean allRequest() default false;
}
