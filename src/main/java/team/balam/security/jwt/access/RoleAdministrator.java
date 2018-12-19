package team.balam.security.jwt.access;

import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.reflections.util.FilterBuilder;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class RoleAdministrator {
    private Map<AccessTarget, AccessRole> accessInfoRepository = new HashMap<>();
    private Set<String> adminRole = new HashSet<>();

    public void init(String... packages) throws AccessInfoExistsException {
        for (String p : packages) {
            Reflections reflections = new Reflections(new ConfigurationBuilder()
                    .setUrls(ClasspathHelper.forPackage(p))
                    .setScanners(new MethodAnnotationsScanner())
                    .filterInputsBy(new FilterBuilder().includePackage(p)));

            Set<Method> methodSet = reflections.getMethodsAnnotatedWith(PathAccess.class);
            for (Method m : methodSet) {
                PathAccess pathAccess = m.getAnnotation(PathAccess.class);
                addNewAccessInfo(new AccessTarget(pathAccess.path()), pathAccess.all(), pathAccess.role());
            }

            methodSet = reflections.getMethodsAnnotatedWith(MethodAccess.class);
            for (Method m: methodSet) {
                MethodAccess methodAccess = m.getAnnotation(MethodAccess.class);
                addNewAccessInfo(new AccessTarget(m.getDeclaringClass(), m.getName()), methodAccess.all(), methodAccess.role());
            }

            methodSet = reflections.getMethodsAnnotatedWith(RestAccess.class);
            for (Method m: methodSet) {
                RestAccess restAccess = m.getAnnotation(RestAccess.class);
                addNewAccessInfo(new AccessTarget(restAccess.uri(), restAccess.method()), restAccess.all(), restAccess.role());
            }
        }
    }

    public void addAdminRole(String adminRole) {
        this.adminRole.add(adminRole);
    }

    private void addNewAccessInfo(AccessTarget target, boolean isAllAccessible, String... roles) throws AccessInfoExistsException {
        for (String role : roles) {
            AccessRole accessRole = accessInfoRepository.get(target);

            if (accessRole == null) {
                accessRole = new AccessRole();
                accessInfoRepository.put(target, accessRole);
            }

            if (isAllAccessible) {
                accessRole.allAccessible();
            } else if (!role.isEmpty() && !accessRole.containsRole(role)) {
                accessRole.addRole(role);
            } else if (accessRole.containsRole(role)) {
                throw new AccessInfoExistsException(target.toString());
            }
        }
    }

    public void checkAuthorization(AccessTarget accessTarget, String role) throws AuthorizationException {
        if (adminRole.contains(role)) {
            return;
        }

        AccessRole accessRole = accessInfoRepository.get(accessTarget);
        if (accessRole != null && !accessRole.containsRole(role)) {
            throw new AuthorizationException("not has access authorization. " + role + " -> " + accessTarget);
        }
    }
}
