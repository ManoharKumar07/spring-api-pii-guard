package io.github.manoharkumar07.piiguard.scan;

import io.github.classgraph.ClassGraph;
import io.github.classgraph.ScanResult;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Discovers {@code @RestController} classes on the classpath using ClassGraph.
 *
 * <p>ClassGraph handles scanning across JARs, nested packages, and module paths —
 * something raw reflection cannot do without fragile manual traversal.
 */
public final class ClasspathScanner {

    /**
     * Finds all classes annotated with {@code @RestController} within the given packages.
     *
     * @param basePackages packages to restrict scanning to; an empty list scans the entire classpath
     * @return discovered controller classes, never {@code null}
     */
    public List<Class<?>> findRestControllers(List<String> basePackages) {
        ClassGraph classGraph = new ClassGraph()
                .enableClassInfo()
                .enableAnnotationInfo();

        if (!basePackages.isEmpty()) {
            classGraph = classGraph.acceptPackages(basePackages.toArray(String[]::new));
        }

        try (ScanResult scanResult = classGraph.scan()) {
            return scanResult
                    .getClassesWithAnnotation(RestController.class.getName())
                    .loadClasses();
        }
    }
}
