# jwt-security
JWT 와 Role 을 통해서 Method, Path, Rest 서비스의 접근제어를 쉽게 도와줍니다.

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
    <version>0.1.0</version>
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
    compile 'team.balam:jwt-security:0.1.0'
}
```

## with spring boot
#### 1. ```team.balam.security.jwt.JwtSecurity``` 의 아래 메소드를 통해서 랜덤 키를 생성하고 config 파일에 저장합니다.

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

#### 2. ```team.balam.security.jwt.JwtSecurity```를 ```javax.servlet.Filter```의 구현체 안에 생성해 줍니다.
```java
@Component
@Slf4j
public class JwtSecurityFilter implements Filter {
    private static JwtSecurity<UserDto> jwtSecurity;
    
    @Value("${jwt.secret}")
    private String jwtSecretKey; // config 에 저장한 키 사용
    
    /**
    *  jwt 발급을 위한 method
    */
    public static String generateJwt(UserDto userDto) {
        return jwtSecurity.generateToken(userDto); 
    }
    
    public static UserDto getAuthUser() {
        return jwtSecurity.getAuthenticationInfo();
    }
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        JwtSecurity.Builder<UserDto> builder = new JwtSecurity.Builder<UserDto>()
                .setPackages("com.westudy") // Spring 의 Rest controller 들이 있는 패키지의 prefix
                .setSecretKey(jwtSecretKey) 
                .setUrlSafe(false) // url safe base 64 참고
                .addAdminRole(Role.ADMIN) // admin role 로 등록되면 모든 서비스를 호출할 수 있습니다. (다수 등록 가능)
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
                    
                    if (userDto.getId() == null) {
                        throw new AuthenticationException();
                    }
                    
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

JwtSecuretiry 의 generic type 은 jwt 의 정보가 메모리에 저장될 때 사용될 객체의 class 를 지정합니다.
jwt <-> User Object

setAuthTokenConverter: JwtSecurity 는 이 method 로 등록된 Function 이 반환하는 AuthToken 을 통해서 jwt 를 생성하게 됩니다.

setObjectConverter: 요청에 포함된 jwt 를 AuthToken 으로 변한하고 이 method 에 등록된 function 을 통해서 개발자가 원하는 객체로 변환한 후 메모리에 저장합니다.
object 로 변환 시 원하는 정보가 없는 등 유효하지 jwt 일 경우 AuthenticationException 을 던져 예외를 전파할 수 있습니다.

#### 3. doFilter method 에 jwt 를 검사하는 로직을 추가해 줍니다.
여기서는 http request header 에 아래와 같은 형식의 헤더를 검사하도록 구현했습니다.
```text
Authorization: Bearer {jwt token}
```
```java
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
        } catch (AuthenticationException | AuthorizationException e) {
            // AuthenticationException 인증 실패
            // AuthorizationException 접근 권한이 없을 경우
            log.error("access deny.", e);
            throw new ServletException(e);
        }

        chain.doFilter(request, response);
    }
```
jwtSecurity.authenticate method 가 실행될 때 예외를 사용하여 클라이언트에 예외를 전파할 수 있습니다.

#### 4. spring 에 JwtSecurityFilter 를 등록해 줍니다.
```java
@Configuration
public class JwtSecurityConfig {
    private JwtSecurityFilter jwtSecurityFilter;

    public JwtSecurityConfig(JwtSecurityFilter jwtSecurityFilter) {
        this.jwtSecurityFilter = jwtSecurityFilter;
    }

    @Bean
    public FilterRegistrationBean<JwtSecurityFilter> jwtSecurityFilterFilterRegistrationBean() {
        FilterRegistrationBean<JwtSecurityFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(jwtSecurityFilter);
        bean.setUrlPatterns(Arrays.asList("/*"));

        return bean;
    }
}
```

#### 5. RestAccess annotation 을 통해서 원하는 제어를 설정해 줍니다.
```java
@RestController
@RequestMapping("/user")
public class UserController {
    private UserService userService;
    
    ...
    
    @GetMapping("/teacher")
    @RestAccess(uri = "/user/teacher", method = "get", role = Role.TEACHER)
    public List<TeacherDto> getTeacherList ...
```
Role.TEACHER 은 String 이고 AuthToken 의 role 이 "teacher" 인 사용자만 접근할 수 있습니다.
구현된 annotation 은 3가지 입니다.
`@MethodAccess`
`@PathAccess`
`@RestAccess` 


만약 jwt 를 받은 모든 사용자가 접근 가능 하도록 하려면 **all**을 사용하면 됩니다.
```
@RestAccess(uri = "/user/teacher", method = "get", all = true)
```

#### 6. 인증이 완료된 사용자에게 jwt 를 발급합니다. (상단의 JwtSecurityFilter 참고)
```java
String jwt = jwtSecurity.generateToken(userDto);
```

메모리에 저장된 객체를 사용하는 방법은 아래와 같습니다.
```
UserDto user = jwtSecurity.getAuthenticationInfo();
```
