package io.github.ManoharKumar07.piiguard.report;

import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;
import io.github.ManoharKumar07.piiguard.engine.Finding;
import io.github.ManoharKumar07.piiguard.model.ScannedEndpoint;
import io.github.ManoharKumar07.piiguard.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HtmlReportGeneratorTest {

    private static final HtmlReportGenerator GENERATOR = new HtmlReportGenerator();

    // -----------------------------------------------------------------------
    // Report file generation
    // -----------------------------------------------------------------------

    @Test
    void createsReportFileAtExpectedPath(@TempDir Path dir) throws IOException {
        AnalysisResult result = emptyResult();
        Path reportPath = GENERATOR.generate(result, dir);

        assertThat(reportPath).exists();
        assertThat(reportPath.getFileName().toString())
                .isEqualTo(HtmlReportGenerator.REPORT_FILE_NAME);
    }

    @Test
    void createsOutputDirectoryIfAbsent(@TempDir Path dir) throws IOException {
        Path nested = dir.resolve("deep").resolve("nested");
        GENERATOR.generate(emptyResult(), nested);
        assertThat(nested).isDirectory();
    }

    @Test
    void returnedPathPointsToExistingFile(@TempDir Path dir) throws IOException {
        Path reportPath = GENERATOR.generate(emptyResult(), dir);
        assertThat(Files.exists(reportPath)).isTrue();
    }

    // -----------------------------------------------------------------------
    // HTML content — empty result
    // -----------------------------------------------------------------------

    @Test
    void reportIsValidHtmlDocument(@TempDir Path dir) throws IOException {
        String html = readReport(dir, emptyResult());
        assertThat(html)
                .startsWith("<!DOCTYPE html>")
                .contains("<html lang=\"en\">")
                .contains("</html>");
    }

    @Test
    void reportContainsLibraryName(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("PII Guard");
    }

    @Test
    void reportContainsTimestamp(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Generated:");
    }

    @Test
    void reportShowsNoFindingsMessageWhenResultIsEmpty(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult()))
                .contains("No PII exposure issues detected");
    }

    @Test
    void reportContainsAllSeverityStatCards(@TempDir Path dir) throws IOException {
        String html = readReport(dir, emptyResult());
        assertThat(html)
                .contains("severity-critical")
                .contains("severity-high")
                .contains("severity-medium")
                .contains("severity-low")
                .contains("severity-info");
    }

    @Test
    void embeddedCssIsPresent(@TempDir Path dir) throws IOException {
        String html = readReport(dir, emptyResult());
        assertThat(html)
                .contains("<style>")
                .contains("</style>")
                .doesNotContain("href=")
                .doesNotContain("src=");
    }

    // -----------------------------------------------------------------------
    // HTML content — result with findings
    // -----------------------------------------------------------------------

    @Test
    void reportContainsFindingsSortedBySeverity(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(),
                List.of(
                        finding("EMAIL_EXPOSURE",    Severity.MEDIUM,   "email",    "GET",  "/api/users"),
                        finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET",  "/api/users"),
                        finding("SSN_EXPOSURE",      Severity.HIGH,     "ssn",      "POST", "/api/users")
                ),
                Instant.now()
        );

        String html = readReport(dir, result);

        // CRITICAL must appear before HIGH, which must appear before MEDIUM in the table.
        int criticalPos = html.indexOf("PASSWORD_EXPOSURE");
        int highPos     = html.indexOf("SSN_EXPOSURE");
        int mediumPos   = html.indexOf("EMAIL_EXPOSURE");
        assertThat(criticalPos).isLessThan(highPos).isLessThan(mediumPos);
    }

    @Test
    void reportContainsFieldNameFromFinding(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "secretPassword", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("secretPassword");
    }

    @Test
    void reportContainsRuleIdFromFinding(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("PASSWORD_EXPOSURE");
    }

    @Test
    void reportContainsEndpointPathFromFinding(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("EMAIL_EXPOSURE", Severity.MEDIUM, "email", "DELETE", "/api/accounts/{id}"));
        assertThat(readReport(dir, result)).contains("/api/accounts/{id}");
    }

    @Test
    void reportSummarizesCorrectSeverityCounts(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(),
                List.of(
                        finding("A", Severity.CRITICAL, "f1", "GET", "/p1"),
                        finding("B", Severity.CRITICAL, "f2", "GET", "/p1"),
                        finding("C", Severity.HIGH,     "f3", "GET", "/p2")
                ),
                Instant.now()
        );
        // The report has a status-danger banner because CRITICAL findings exist.
        assertThat(readReport(dir, result)).contains("status-danger");
    }

    @Test
    void reportShowsStatusCleanWhenNoFindings(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("status-clean");
    }

    @Test
    void reportShowsStatusWarningForMediumFindings(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("ADDR", Severity.MEDIUM, "address", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("status-warning");
    }

    // -----------------------------------------------------------------------
    // HTML escaping
    // -----------------------------------------------------------------------

    @Test
    void escapesAmpersand() {
        assertThat(HtmlReportGenerator.esc("a&b")).isEqualTo("a&amp;b");
    }

    @Test
    void escapesLessThan() {
        assertThat(HtmlReportGenerator.esc("<script>")).isEqualTo("&lt;script&gt;");
    }

    @Test
    void escapesDoubleQuote() {
        assertThat(HtmlReportGenerator.esc("say \"hi\"")).isEqualTo("say &quot;hi&quot;");
    }

    @Test
    void escNullReturnsEmptyString() {
        assertThat(HtmlReportGenerator.esc(null)).isEmpty();
    }

    @Test
    void maliciousFieldNameIsEscaped(@TempDir Path dir) throws IOException {
        Finding malicious = new Finding(
                "RULE", Severity.HIGH, "Cat",
                "<script>alert('xss')</script>",   // fieldName
                "<script>",                         // fieldJsonName
                "com.example.Dto",
                "/api/test", "GET", "com.example.Controller",
                "message", "recommendation", false, true
        );
        String html = readReport(dir, resultWithFinding(malicious));
        assertThat(html)
                .doesNotContain("<script>alert(")
                .contains("&lt;script&gt;");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static AnalysisResult emptyResult() {
        return new AnalysisResult(List.of(), List.of(), Instant.now());
    }

    private static AnalysisResult resultWithFinding(Finding f) {
        return new AnalysisResult(List.of(), List.of(f), Instant.now());
    }

    private static Finding finding(String ruleId, Severity severity,
                                   String fieldName, String method, String path) {
        return new Finding(
                ruleId, severity, "TestCategory",
                fieldName, fieldName,
                "com.example.TestDto",
                path, method, "com.example.TestController",
                "Test message",
                "Test recommendation",
                false, true
        );
    }

    private String readReport(Path dir, AnalysisResult result) throws IOException {
        Path reportPath = GENERATOR.generate(result, dir);
        return Files.readString(reportPath);
    }
}
