# jwt-security
JWT 와 Role 을 통해서 Method, Path, Rest 서비스의 접근제어를 쉽게 도와줍니다.

## Maven
```xml
<repositories>
    <repository>
        <id>knero-mvn-repo</id>
        <url>https://github.com/KNero/repository/raw/master/maven</url>
    </repository>
</repositories>
```
```xml
<dependency>
    <groupId>team.balam</groupId>
    <artifactId>jwt-security</artifactId>
    <version>0.1.5</version>
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
    compile 'team.balam:jwt-security:0.1.5'
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
public class JwtSecurityFilter extends JwtFilter<UserDto> {
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
    protected JwtSecurity<Map> build(JwtSecurity.Builder<UserDto> builder, FilterConfig filterConfig) 
    throws ServletException {
        builder.setPackages("com.balam") // Spring 의 Rest controller 들이 있는 패키지의 prefix
                .setSecretKey(jwtSecretKey) 
                .setUrlSafe(false) // url safe base 64 참고
                .addAdminRole(Role.ADMIN) // admin role 로 등록되면 모든 서비스를 호출할 수 있습니다. (다수 등록 가능)
                .addPrefix("/user") // prefix 를 통해서 하위 paht, rest uri 를 모두 검사할 수 있습니다.
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

        return builder.build();
    }
```

JwtSecuretiry 의 generic type 은 jwt 의 정보가 메모리에 저장될 때 사용될 객체의 class 를 지정합니다.
jwt <-> User Object

setAuthTokenConverter: JwtSecurity 는 이 method 로 등록된 Function 이 반환하는 AuthToken 을 통해서 jwt 를 생성하게 됩니다.

setObjectConverter: 요청에 포함된 jwt 를 AuthToken 으로 변한하고 이 method 에 등록된 function 을 통해서 개발자가 원하는 객체로 변환한 후 메모리에 저장합니다.
object 로 변환 시 원하는 정보가 없는 등 유효하지 jwt 일 경우 AuthenticationException 을 던져 예외를 전파할 수 있습니다.

(addPrefix 를 사용하고 Access annotation 을 정의하지 않을 경우 admin role 만 접근 가능) 

#### 3. jwt 요청 및 예외 처리
여기서는 http request header 에 아래와 같은 형식의 헤더를 추가하여 요청해야 합니다.
```text
Authorization: Bearer {jwt token}
```
```java
실행될 때 예외를 사용하여 클라이언트에 예외를 전파할 수 있으며 예외는 아래의 메소드를 통해 전달 받습니다.
```java
@Override
    protected void onFailAuthentication(ServletRequest request, ServletResponse response, AuthenticationException e) throws ServletException {
        super.onFailAuthentication(request, response, e);
    }

    @Override
    protected void onFailAuthorization(ServletRequest request, ServletResponse response, AuthorizationException e) throws ServletException {
        log.error("Unauthorized request. {}", jwtSecurity.getAuthenticationInfo());
        super.onFailAuthorization(request, response, e);
    }
```
#### 4. RestAccess annotation 을 통해서 원하는 제어를 설정해 줍니다.
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


만약 jwt 를 받은 모든 사용자가 접근 가능 하도록 하려면 `allRole`을 사용하면 됩니다. (모든 Role 사용 가능)
```
@RestAccess(uri = "/user/teacher", method = "get", allRole = true)
```

PathVariable 을 사용할 경우에는 아래와 같이 `*` 을 사용해 줍니다.
`*` 는 하위를 모두 포함하지 않기 때문에 여러 두 개를 사용할 경우 `/*/*` 와 같이 각 부분에 모두 설정해야 합니다.
```
@RestAccess(uri = "/user/teacher/*", method = "get", allRole = true)
```

만약 prefix 에 의해서 접근 권한이 필요한 서비스 중 권한없이 접근 가능 하다록 예외를 두고 싶다면 'allRequest' 를 설정해 준다. (모든 요청 사용 가능)
```
@RestAccess(uri = "/user/teacher", method = "get", allRequest = true)
```

#### 7. 인증이 완료된 사용자에게 jwt 를 발급합니다. (상단의 build 메소드 참고)
```java
String jwt = jwtSecurity.generateToken(userDto);
```

메모리에 저장된 객체를 사용하는 방법은 아래와 같습니다.
```
UserDto user = jwtSecurity.getAuthenticationInfo();
```

#### spring web security 와 같이 사용할 경우 login success handler 에서 jwt 토큰을 발급해 주는 것이 좋습니다.
```java
http.authorizeRequests()
                .antMatchers("/", "/resources/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .successHandler((request, response, authentication) -> {
                    // jwt 발급
                })
```
