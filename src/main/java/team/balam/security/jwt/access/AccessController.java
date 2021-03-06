package team.balam.security.jwt.access;

import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.reflections.util.FilterBuilder;

import java.lang.reflect.Method;
import java.util.*;

public class AccessController {
    private Map<AccessTarget, AccessRole> generalTargetRepository = new HashMap<>();
    private Map<AccessTarget, AccessRole> wildcardTargetRepository = new HashMap<>();

    private Set<String> adminRole = new HashSet<>();
    private List<String> prefixList = new ArrayList<>();
    private List<String> ignorePrefixList = new ArrayList<>();

    public void addPrefix(String prefix) {
        this.prefixList.add(prefix);
    }

    public void addIgnorePrefix(String prefix) {
        ignorePrefixList.add(prefix);
    }

    public void init(String... packages) throws AccessInfoExistsException {
        for (String p : packages) {
            Reflections reflections = new Reflections(new ConfigurationBuilder()
                    .setUrls(ClasspathHelper.forPackage(p))
                    .setScanners(new MethodAnnotationsScanner())
                    .filterInputsBy(new FilterBuilder().includePackage(p)));

            Set<Method> methodSet = reflections.getMethodsAnnotatedWith(PathAccess.class);
            for (Method m : methodSet) {
                PathAccess pathAccess = m.getAnnotation(PathAccess.class);
                addNewAccessInfo(new AccessTarget(pathAccess.path()),
                        pathAccess.allRole(), pathAccess.allRequest(), pathAccess.role());
            }

            methodSet = reflections.getMethodsAnnotatedWith(MethodAccess.class);
            for (Method m: methodSet) {
                MethodAccess methodAccess = m.getAnnotation(MethodAccess.class);
                addNewAccessInfo(new AccessTarget(m.getDeclaringClass(), m.getName()),
                        methodAccess.allRole(), methodAccess.allRequest(), methodAccess.role());
            }

            methodSet = reflections.getMethodsAnnotatedWith(RestAccess.class);
            for (Method m: methodSet) {
                RestAccess restAccess = m.getAnnotation(RestAccess.class);
                addNewAccessInfo(new AccessTarget(restAccess.uri(), restAccess.method()),
                        restAccess.allRole(), restAccess.allRequest(), restAccess.role());
            }
        }
    }

    public void addAdminRole(String adminRole) {
        this.adminRole.add(adminRole);
    }

    private void addNewAccessInfo(AccessTarget target, boolean isAllRole, boolean isAllRequest, String... roles)
            throws AccessInfoExistsException {
        for (String role : roles) {
            AccessRole accessRole;

            if (target.isWildcard()) {
                accessRole = wildcardTargetRepository.get(target);
            } else {
                accessRole = generalTargetRepository.get(target);
            }

            if (accessRole == null) {
                accessRole = new AccessRole();

                if (target.isWildcard()) {
                    wildcardTargetRepository.put(target, accessRole);
                } else {
                    generalTargetRepository.put(target, accessRole);
                }
            }

            if (isAllRole) {
                accessRole.allRoleAccessible();
            } else if (isAllRequest) {
                accessRole.allRequestAccessible();
            } else if (!role.isEmpty() && !accessRole.containsRole(role)) {
                accessRole.addRole(role);
            } else if (accessRole.containsRole(role)) {
                throw new AccessInfoExistsException(target + " / " + accessRole);
            }
        }
    }

    public void checkAuthorization(AccessTarget accessTarget, String role) throws AuthorizationException {
        if (adminRole.contains(role)) {
            return;
        }

        for (String ignore: ignorePrefixList) {
            if (accessTarget.containsPrefix(ignore)) {
                return;
            }
        }

        for (String prefix : prefixList) {
            if (accessTarget.containsPrefix(prefix)) {
                AccessRole accessRole = getAccessRole(accessTarget);

                if (accessRole == null) { // RestAccess 가 없다면 admin 만 접근 가능
                    throw new AuthorizationException("not has access authorization. role is empty -> " + accessTarget);
                } else if (!accessRole.containsRole(role)) { // RestAccess 에 role 이 정해져 있다면 필터링한다.
                    throw new AuthorizationException("not has access authorization. " + role + " -> " + accessTarget);
                }
            }
        }

        AccessRole accessRole = getAccessRole(accessTarget);
        if (accessRole != null && !accessRole.containsRole(role)) {
            throw new AuthorizationException("not has access authorization. " + role + " -> " + accessTarget);
        }
    }

    private AccessRole getAccessRole(AccessTarget accessTarget) {
        AccessRole role = generalTargetRepository.get(accessTarget);

        if (role == null) {
            role = wildcardTargetRepository.get(accessTarget);
        }

        return role;
    }
}
