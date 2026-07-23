package io.github.ManoharKumar07.piiguard.extension;

import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;
import io.github.ManoharKumar07.piiguard.engine.Finding;
import io.github.ManoharKumar07.piiguard.model.Severity;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PiiGuardAssertionErrorTest {

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static Finding finding(String ruleId, Severity severity,
                                   String fieldName, String method, String path) {
        return new Finding(
                ruleId, severity, "TestCategory",
                fieldName, fieldName,
                "com.example.TestDto",
                path, method, "com.example.TestController",
                "Test message", "Test recommendation",
                false, true
        );
    }

    private static PiiGuardAssertionError errorWith(Finding... findings) {
        AnalysisResult result = new AnalysisResult(
                List.of(), List.of(findings), Instant.now());
        return new PiiGuardAssertionError(
                Path.of("target", "pii-guard", "pii-guard-report.html"),
                result);
    }

    // -----------------------------------------------------------------------
    // Type hierarchy
    // -----------------------------------------------------------------------

    @Test
    void isAssertionError() {
        assertThat(errorWith()).isInstanceOf(AssertionError.class);
    }

    // -----------------------------------------------------------------------
    // Message content
    // -----------------------------------------------------------------------

    @Test
    void messageContainsFindingCount() {
        PiiGuardAssertionError error = errorWith(
                finding("PWD", Severity.CRITICAL, "password", "GET", "/api/users"),
                finding("SSN", Severity.HIGH,     "ssn",      "GET", "/api/users")
        );
        assertThat(error.getMessage()).contains("2 potential sensitive data exposure");
    }

    @Test
    void messageContainsSeverityLabel() {
        PiiGuardAssertionError error = errorWith(
                finding("PWD", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(error.getMessage()).contains("CRITICAL");
    }

    @Test
    void messageContainsRuleId() {
        PiiGuardAssertionError error = errorWith(
                finding("PASSWORD_IN_RESPONSE", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(error.getMessage()).contains("PASSWORD_IN_RESPONSE");
    }

    @Test
    void messageContainsFieldName() {
        PiiGuardAssertionError error = errorWith(
                finding("PWD", Severity.CRITICAL, "secretPassword", "GET", "/api/users"));
        assertThat(error.getMessage()).contains("secretPassword");
    }

    @Test
    void messageContainsHttpMethodAndPath() {
        PiiGuardAssertionError error = errorWith(
                finding("SSN", Severity.HIGH, "ssn", "DELETE", "/api/accounts/{id}"));
        assertThat(error.getMessage())
                .contains("DELETE")
                .contains("/api/accounts/{id}");
    }

    @Test
    void messageContainsDtoSimpleClassName() {
        PiiGuardAssertionError error = errorWith(
                finding("SSN", Severity.HIGH, "ssn", "GET", "/api/users"));
        // Fully-qualified name is com.example.TestDto; simple name must appear in message.
        assertThat(error.getMessage()).contains("TestDto");
    }

    @Test
    void messageContainsReportPath() {
        PiiGuardAssertionError error = errorWith(
                finding("PWD", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(error.getMessage()).contains("pii-guard-report.html");
    }

    @Test
    void messageContainsAllFindings() {
        PiiGuardAssertionError error = errorWith(
                finding("PWD",   Severity.CRITICAL, "password", "GET", "/api/users"),
                finding("EMAIL", Severity.MEDIUM,   "email",    "GET", "/api/users"),
                finding("SSN",   Severity.HIGH,     "ssn",      "POST", "/api/signup")
        );
        assertThat(error.getMessage())
                .contains("PWD")
                .contains("EMAIL")
                .contains("SSN");
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    @Test
    void getResultReturnsStoredResult() {
        AnalysisResult result = new AnalysisResult(List.of(), List.of(), Instant.now());
        PiiGuardAssertionError error = new PiiGuardAssertionError(
                Path.of("target/pii-guard/pii-guard-report.html"), result);
        assertThat(error.getResult()).isSameAs(result);
    }

    @Test
    void getReportPathReturnsStoredPath() {
        Path path = Path.of("target", "pii-guard", "pii-guard-report.html");
        AnalysisResult result = new AnalysisResult(List.of(), List.of(), Instant.now());
        PiiGuardAssertionError error = new PiiGuardAssertionError(path, result);
        assertThat(error.getReportPath()).isEqualTo(path);
    }

    @Test
    void zeroFindingsMessageIsStillValid() {
        PiiGuardAssertionError error = errorWith();
        assertThat(error.getMessage())
                .contains("0 potential")
                .isNotBlank();
    }
}
