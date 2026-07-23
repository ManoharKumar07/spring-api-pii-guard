package io.github.manoharkumar07.piiguard.scan;

import io.github.manoharkumar07.piiguard.fixtures.controllers.CircularController;
import io.github.manoharkumar07.piiguard.fixtures.controllers.SafeProductController;
import io.github.manoharkumar07.piiguard.fixtures.controllers.SensitiveDataController;
import io.github.manoharkumar07.piiguard.fixtures.controllers.SuppressedFieldController;
import io.github.manoharkumar07.piiguard.fixtures.controllers.VulnerableUserController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClasspathScannerTest {

    private ClasspathScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new ClasspathScanner();
    }

    @Test
    void findsRestControllersInSpecifiedPackage() {
        List<Class<?>> controllers = scanner.findRestControllers(
                List.of("io.github.manoharkumar07.piiguard.fixtures.controllers"));

        assertThat(controllers)
                .containsExactlyInAnyOrder(
                        VulnerableUserController.class,
                        SafeProductController.class,
                        SuppressedFieldController.class,
                        SensitiveDataController.class,
                        CircularController.class);
    }

    @Test
    void returnsEmptyListForPackageWithNoControllers() {
        List<Class<?>> controllers = scanner.findRestControllers(
                List.of("io.github.manoharkumar07.piiguard.fixtures.dto"));

        assertThat(controllers).isEmpty();
    }

    @Test
    void findsControllersAcrossSubPackages() {
        // Scanning the parent package should discover controllers in child packages
        List<Class<?>> controllers = scanner.findRestControllers(
                List.of("io.github.manoharkumar07.piiguard.fixtures"));

        assertThat(controllers).hasSizeGreaterThanOrEqualTo(2);
        assertThat(controllers).contains(VulnerableUserController.class, SafeProductController.class);
    }

    @Test
    void returnsEmptyListForNonExistentPackage() {
        List<Class<?>> controllers = scanner.findRestControllers(
                List.of("com.does.not.exist"));

        assertThat(controllers).isEmpty();
    }
}
