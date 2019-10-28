package team.balam.security.jwt;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Date;
import java.util.Map;

@Getter
@Builder
@ToString
public class AuthToken {
    private String issuer; // iss
    private String subject; // sub
    private String audience; // aud
    private Date expirationTime; // exp
    private String jwtId; // jti
    private Date notBefore; // nbf
    private Date issuedAt; // iat

    private String role;
    private Map<String, Object> info;
}
