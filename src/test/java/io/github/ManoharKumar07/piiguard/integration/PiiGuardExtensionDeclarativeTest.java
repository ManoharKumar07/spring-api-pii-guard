package io.github.ManoharKumar07.piiguard.integration;

import io.github.ManoharKumar07.piiguard.extension.PiiGuardExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration test using the <em>declarative</em>
 * {@code @ExtendWith(PiiGuardExtension.class)} approach.
 *
 * <p>The extension is configured with its zero-argument constructor (defaults):
 * <ul>
 *   <li>{@code failOnFindings = false} — findings are logged but tests always pass</li>
 *   <li>{@code minimumSeverity = HIGH}</li>
 *   <li>{@code reportOutputDirectory = target/pii-guard}</li>
 * </ul>
 *
 * <p>Base-package auto-detection: the extension scans the classpath for a class annotated
 * with {@code @SpringBootApplication}. {@code TestSpringBootApplication} in
 * {@code io.github.ManoharKumar07.piiguard.fixtures} satisfies this requirement,
 * so the extension automatically scans the fixtures package without any extra config.
 *
 * <p>These tests verify the complete pipeline by inspecting the generated report file —
 * the only observable output available to test methods when using the declarative
 * {@code @ExtendWith} style (no instance reference is held).
 */
@ExtendWith(PiiGuardExtension.class)
class PiiGuardExtensionDeclarativeTest {

    private static final Path DEFAULT_REPORT =
            Path.of("target", "pii-guard", "pii-guard-report.html");

    @Test
    void reportFileIsWrittenToDefaultDirectory() {
        assertThat(DEFAULT_REPORT).exists();
    }

    @Test
    void reportFileIsNonEmpty() throws IOException {
        assertThat(Files.size(DEFAULT_REPORT)).isGreaterThan(0);
    }

    @Test
    void reportContainsPiiGuardBranding() throws IOException {
        String html = Files.readString(DEFAULT_REPORT);
        assertThat(html).contains("PII Guard");
    }

    @Test
    void reportContainsCriticalSeverityBadge() throws IOException {
        // VulnerableUserController exposes password fields → CRITICAL findings expected.
        String html = Files.readString(DEFAULT_REPORT);
        assertThat(html).contains("severity-critical");
    }
}
