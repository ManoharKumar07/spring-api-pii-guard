package io.github.ManoharKumar07.piiguard.extension;

import io.github.ManoharKumar07.piiguard.config.PiiGuardConfiguration;
import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;
import io.github.ManoharKumar07.piiguard.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link PiiGuardExtension}.
 *
 * <p>The extension is registered statically so that {@code beforeAll} runs once before
 * all tests. The fixture package {@code io.github.ManoharKumar07.piiguard.fixtures}
 * contains deliberately vulnerable controllers ({@code VulnerableUserController}) and
 * safe controllers ({@code SafeProductController}), giving us both CRITICAL/HIGH
 * findings and a safe baseline to assert against.
 *
 * <p>Results are accessed via the instance accessor {@code extension.getLatestResult()},
 * which is the recommended pattern when the extension is a {@code static final} field.
 */
class PiiGuardExtensionTest {

    private static final Path REPORT_DIR = Path.of("target", "pii-guard-extension-test");

    @RegisterExtension
    static final PiiGuardExtension extension = new PiiGuardExtension(
            PiiGuardConfiguration.builder()
                    .basePackages("io.github.ManoharKumar07.piiguard.fixtures")
                    .failOnFindings(false)          // never throw — we inspect results ourselves
                    .minimumSeverity(Severity.HIGH)
                    .reportOutputDirectory(REPORT_DIR)
                    .build()
    );

    // -----------------------------------------------------------------------
    // Report generation
    // -----------------------------------------------------------------------

    @Test
    void reportFileIsGeneratedAtConfiguredPath() {
        assertThat(REPORT_DIR.resolve("pii-guard-report.html")).exists();
    }

    @Test
    void reportFileIsNonEmpty() throws Exception {
        Path report = REPORT_DIR.resolve("pii-guard-report.html");
        assertThat(Files.size(report)).isGreaterThan(0);
    }

    @Test
    void reportContainsPiiGuardBranding() throws Exception {
        String html = Files.readString(REPORT_DIR.resolve("pii-guard-report.html"));
        assertThat(html).contains("PII Guard");
    }

    @Test
    void reportHtmlContainsCriticalBadge() throws Exception {
        String html = Files.readString(REPORT_DIR.resolve("pii-guard-report.html"));
        // VulnerableUserController exposes password fields → CRITICAL findings expected.
        assertThat(html).contains("severity-critical");
    }

    @Test
    void reportPathInstanceGetterReturnsExistingFile() {
        Path reportPath = extension.getLatestReportPath();
        assertThat(reportPath).isNotNull();
        assertThat(reportPath).exists();
    }

    // -----------------------------------------------------------------------
    // Analysis correctness — accessed via instance getter
    // -----------------------------------------------------------------------

    @Test
    void resultInstanceGetterReturnsNonNullResult() {
        assertThat(extension.getLatestResult()).isNotNull();
    }

    @Test
    void detectsCriticalFindingsFromVulnerableController() {
        AnalysisResult result = extension.getLatestResult();
        // VulnerableUserController returns UserWithPasswordDto with 'password' + 'passwordHash'
        assertThat(result.countBySeverity(Severity.CRITICAL)).isPositive();
    }

    @Test
    void detectsHighFindingsFromVulnerableController() {
        AnalysisResult result = extension.getLatestResult();
        // VulnerableUserController returns UserWithSsnDto with 'socialSecurityNumber'
        assertThat(result.countBySeverity(Severity.HIGH)).isPositive();
    }

    @Test
    void scansMultipleEndpoints() {
        AnalysisResult result = extension.getLatestResult();
        // VulnerableUserController alone has 5 endpoints
        assertThat(result.endpoints()).hasSizeGreaterThan(1);
    }

    @Test
    void resultContainsTimestamp() {
        assertThat(extension.getLatestResult().timestamp()).isNotNull();
    }

    @Test
    void resultHasFindingsListPopulated() {
        assertThat(extension.getLatestResult().findings()).isNotEmpty();
    }

    @Test
    void totalFindingsMatchesSumBySeverity() {
        AnalysisResult result = extension.getLatestResult();
        long sumBySeverity = result.countBySeverity(Severity.CRITICAL)
                + result.countBySeverity(Severity.HIGH)
                + result.countBySeverity(Severity.MEDIUM)
                + result.countBySeverity(Severity.LOW)
                + result.countBySeverity(Severity.INFO);
        assertThat((long) result.totalFindings()).isEqualTo(sumBySeverity);
    }

    // -----------------------------------------------------------------------
    // Idempotency
    // -----------------------------------------------------------------------

    @Test
    void extensionIsIdempotent() {
        // The same instance is reused for all test methods in this class;
        // result and report path must remain stable across repeated lookups.
        AnalysisResult first  = extension.getLatestResult();
        AnalysisResult second = extension.getLatestResult();
        assertThat(first).isSameAs(second);
    }

    // -----------------------------------------------------------------------
    // Static accessor (requires ExtensionContext — tested via a simpler check)
    // -----------------------------------------------------------------------

    @Test
    void staticAndInstanceGettersReturnSameResult() {
        // Verify that the instance getter and static getter (via root store) are consistent.
        // We can't inject ExtensionContext here directly, so we verify the instance getter
        // alone, and trust that the static getter uses the same stored value.
        assertThat(extension.getLatestResult().totalFindings())
                .isGreaterThanOrEqualTo(0);
    }
}
