package team.balam.security.jwt;

import lombok.Builder;
import lombok.Getter;

import java.util.Date;
import java.util.Map;

@Getter
@Builder
public class AuthToken {
    private String role;
    private Map<String, Object> info;
    private Date expirationTime;
}
