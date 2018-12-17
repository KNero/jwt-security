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
                addPathAccess(pathAccess.path(), pathAccess.role());
            }

            methodSet = reflections.getMethodsAnnotatedWith(MethodAccess.class);
            for (Method m: methodSet) {
                MethodAccess methodAccess = m.getAnnotation(MethodAccess.class);
                addMethodAccess(m.getDeclaringClass(), m.getName(), methodAccess.role());
            }
        }
    }

    public void addAdminRole(String adminRole) {
        this.adminRole.add(adminRole);
    }

    public void addPathAccess(String path, String... role) throws AccessInfoExistsException {
        addNewAccessInfo(new AccessTarget(path), role);
    }

    public void addMethodAccess(Class type, String method, String... role) throws AccessInfoExistsException {
        addNewAccessInfo(new AccessTarget(type, method), role);
    }

    private void addNewAccessInfo(AccessTarget target, String... roles) throws AccessInfoExistsException {
        AccessRole accessRole = accessInfoRepository.get(target);

        for (String role : roles) {
            if (accessRole == null) {
                accessInfoRepository.put(target, new AccessRole().addRole(role));
            } else if (!accessRole.containsRole(role)) {
                accessRole.addRole(role);
            } else {
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
