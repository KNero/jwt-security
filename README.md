# jwt-security
## Maven
```xml
<repositories>
    <repository>
        <id>exof-maven</id>
        <url>https://github.com/KNero/repository/raw/master/maven</url>
    </repository>
</repositories>
```
```xml
<dependency>
    <groupId>team.balam</groupId>
    <artifactId>jwt-security</artifactId>
    <version>0.0.1</version>
</dependency>
```
## Gradle
```gradle
repositories {
    maven {
        mavenLocal()
        maven {
            url "https://github.com/KNero/repository/raw/master/maven"
        }
    }
}
```
```gradle
dependencies {
    compile 'team.balam:jwt-security:0.0.6'
}
```

### with spring boot
#### 1. ```team.balam.security.jwt.JwtSecurity``` 의 아래 메소드를 통해서 랜덤 키를 생성하고 config 파일에 저장한다.

```java
JwtSecurity.create64BitesSecretKey()
JwtSecurity.create48BitesSecretKey()
JwtSecurity.create32BitesSecretKey()
```

application.yaml
```yaml
jwt:
  secret: 13830a69d73c4945aa2de40a3664f469c9204422cdef475785fcc342ab5eee0f
```

#### 1. ```team.balam.security.jwt.JwtSecurity```를 ```javax.servlet.Filter```의 구현체 안에 생성해 준다.
```java
@Component
@Slf4j
public class JwtSecurityFilter implements Filter {
    private static JwtSecurity<UserDto> jwtSecurity;
    
    @Value("${jwt.secret}")
    private String jwtSecretKey; // 에 저장한 키 사용
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        JwtSecurity.Builder<UserDto> builder = new JwtSecurity.Builder<UserDto>()
                .setPackages("com.westudy") // Spring 의 Rest controller 들이 있는 패키지의 prefix
                .setSecretKey(jwtSecretKey) 
                .setUrlSafe(false) /url safe base 64 참고
                .addAdminRole(Role.ADMIN) // admin role 로 등록되면 모든 서비스를 호출할 수 있다.
                .setAuthTokenConverter(userDto -> {
                    String role = Role.NONE;
                    if (userDto instanceof StudentDto) {
                        role = Role.STUDENT;
                    } else if (userDto instanceof TeacherDto) {
                        role = Role.TEACHER;
                    }

                    HashMap<String, Object> userData = new HashMap<>();
                    userData.put("id", userDto.getId());
                    userData.put("email", userDto.getEmail());
                    userData.put("image", userDto.getImage());
                    userData.put("isTeacher", Role.TEACHER.equals(role));

                    return AuthToken.builder().role(role).info(userData).build();
                })
                .setObjectConverter(authToken -> {
                    Map<String, Object> info = authToken.getInfo();

                    UserDto userDto = new UserDto();
                    userDto.setId((String) info.get("id"));
                    userDto.setEmail((String) info.get("email"));
                    userDto.setImage((String) info.get("image"));
                    return userDto;
                });

        try {
            jwtSecurity = builder.build();
        } catch (AccessInfoExistsException e) {
            log.error("Access info already exists.", e);
            throw new ServletException(e);
        }
    }
```

JwtSecuretiry 의 generic type 은 jwt 의 정보가 메모리에 저장될 때 사용될 객체의 class 를 지정한다.
jwt <-> User Object

setAuthTokenConverter : JwtSecurity 
