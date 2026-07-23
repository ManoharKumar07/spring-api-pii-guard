package io.github.ManoharKumar07.piiguard.fixtures;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Marker class that allows {@link io.github.ManoharKumar07.piiguard.extension.PiiGuardExtension}
 * to auto-detect the base package when used with the declarative {@code @ExtendWith} approach.
 *
 * <p>The extension's package-resolution logic scans the classpath for a class annotated
 * with {@code @SpringBootApplication} and uses its package as the scan root. By placing
 * this class in {@code io.github.ManoharKumar07.piiguard.fixtures}, the declarative
 * integration tests automatically scan all fixture controllers without requiring explicit
 * package configuration.
 *
 * <p><strong>Note:</strong> This class is in {@code src/test/java} and only present
 * on the test classpath. It does not start a Spring Boot application context —
 * PiiGuardExtension uses ClassGraph for bytecode-level annotation scanning only.
 */
@SpringBootApplication
public class TestSpringBootApplication {
    // Marker class — intentionally empty.
}
