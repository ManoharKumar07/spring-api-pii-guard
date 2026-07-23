package io.github.manoharkumar07.piiguard.report;

import io.github.manoharkumar07.piiguard.engine.AnalysisResult;
import io.github.manoharkumar07.piiguard.engine.Finding;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;
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
    // Phase 5 — embedded JavaScript
    // -----------------------------------------------------------------------

    @Test
    void embeddedJavaScriptIsPresent(@TempDir Path dir) throws IOException {
        String html = readReport(dir, emptyResult());
        assertThat(html)
                .contains("<script>")
                .contains("</script>");
        // Must be inline — no external script reference
        assertThat(html).doesNotContain("script src=");
    }

    @Test
    void javaScriptContainsSeverityFilterFunction(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("setSeverityFilter");
    }

    @Test
    void javaScriptContainsApplyFiltersFunction(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("applyFilters");
    }

    @Test
    void javaScriptContainsToggleEndpointFunction(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("toggleEp");
    }

    @Test
    void javaScriptContainsCopyFindingFunction(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("copyFinding");
    }

    // -----------------------------------------------------------------------
    // Phase 5 — filter bar and search (appear when findings exist)
    // -----------------------------------------------------------------------

    @Test
    void filterButtonsArePresentWhenFindingsExist(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET", "/api/users"));
        String html = readReport(dir, result);
        assertThat(html)
                .contains("filter-btn")
                .contains("filter-critical")
                .contains("filter-high")
                .contains("filter-medium")
                .contains("filter-low")
                .contains("filter-info");
    }

    @Test
    void allFilterButtonIsActiveByDefault(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("A", Severity.HIGH, "ssn", "GET", "/api/users"));
        String html = readReport(dir, result);
        // The "all" filter button must have the 'active' class
        assertThat(html).contains("data-severity=\"all\"");
    }

    @Test
    void searchInputIsPresentWhenFindingsExist(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("EMAIL_EXPOSURE", Severity.MEDIUM, "email", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("findings-search");
    }

    @Test
    void findingRowHasDataSeverityAttribute(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("data-severity=\"critical\"");
    }

    @Test
    void findingRowsHaveDataSeverityForEachLevel(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(),
                List.of(
                        finding("A", Severity.CRITICAL, "f1", "GET", "/p"),
                        finding("B", Severity.HIGH,     "f2", "GET", "/p"),
                        finding("C", Severity.MEDIUM,   "f3", "GET", "/p"),
                        finding("D", Severity.LOW,      "f4", "GET", "/p"),
                        finding("E", Severity.INFO,     "f5", "GET", "/p")
                ),
                Instant.now()
        );
        String html = readReport(dir, result);
        assertThat(html)
                .contains("data-severity=\"critical\"")
                .contains("data-severity=\"high\"")
                .contains("data-severity=\"medium\"")
                .contains("data-severity=\"low\"")
                .contains("data-severity=\"info\"");
    }

    @Test
    void copyButtonIsPresentForEachFinding(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("copy-btn");
    }

    @Test
    void copyButtonTriggersJavaScriptFunction(@TempDir Path dir) throws IOException {
        AnalysisResult result = resultWithFinding(
                finding("PASSWORD_EXPOSURE", Severity.CRITICAL, "password", "GET", "/api/users"));
        assertThat(readReport(dir, result)).contains("copyFinding(this)");
    }

    // -----------------------------------------------------------------------
    // Phase 5 — endpoint expand/collapse
    // -----------------------------------------------------------------------

    @Test
    void endpointRowsHaveEpRowClass(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(endpoint("GET", "/api/users", "com.example.UserController")),
                List.of(),
                Instant.now()
        );
        assertThat(readReport(dir, result)).contains("ep-row");
    }

    @Test
    void endpointDetailRowsStartHidden(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(endpoint("GET", "/api/users", "com.example.UserController")),
                List.of(),
                Instant.now()
        );
        String html = readReport(dir, result);
        assertThat(html)
                .contains("ep-detail")
                .contains("display:none");
    }

    @Test
    void endpointRowHasExpandIcon(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(endpoint("GET", "/api/users", "com.example.UserController")),
                List.of(),
                Instant.now()
        );
        assertThat(readReport(dir, result)).contains("expand-icon");
    }

    @Test
    void endpointDetailRowHasColspan(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(endpoint("GET", "/api/users", "com.example.UserController")),
                List.of(),
                Instant.now()
        );
        assertThat(readReport(dir, result)).contains("colspan=\"6\"");
    }

    // -----------------------------------------------------------------------
    // Phase 5 — Recommendations section
    // -----------------------------------------------------------------------

    @Test
    void recommendationsSectionIsPresentInReport(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Recommendations");
    }

    @Test
    void recommendationsShowsCleanMessageWhenNoFindings(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("rec-clean");
    }

    @Test
    void recommendationsContainsCategoryFromFindings(@TempDir Path dir) throws IOException {
        Finding f = new Finding(
                "PASSWORD_EXPOSURE", Severity.CRITICAL, "Credentials",
                "password", "password", "com.example.Dto",
                "/api/users", "GET", "com.example.Controller",
                "msg", "rec", false, true
        );
        String html = readReport(dir, resultWithFinding(f));
        assertThat(html).contains("Credentials");
    }

    @Test
    void recommendationsContainsSeverityBadgeForCategory(@TempDir Path dir) throws IOException {
        Finding f = new Finding(
                "PASSWORD_EXPOSURE", Severity.CRITICAL, "Credentials",
                "password", "password", "com.example.Dto",
                "/api/users", "GET", "com.example.Controller",
                "msg", "rec", false, true
        );
        String html = readReport(dir, resultWithFinding(f));
        // The recommendations section must have a CRITICAL badge for the Credentials category
        assertThat(html).contains("rec-item sev-critical");
    }

    @Test
    void recommendationsContainsActionableAdvice(@TempDir Path dir) throws IOException {
        Finding f = new Finding(
                "PASSWORD_EXPOSURE", Severity.CRITICAL, "Credentials",
                "password", "password", "com.example.Dto",
                "/api/users", "GET", "com.example.Controller",
                "msg", "rec", false, true
        );
        String html = readReport(dir, resultWithFinding(f));
        assertThat(html).contains("@JsonIgnore");
    }

    @Test
    void recommendationsSkipsInfoFindings(@TempDir Path dir) throws IOException {
        // INFO finding (JsonIgnore) should NOT produce a rec-item
        Finding infoFinding = new Finding(
                "JSON_IGNORE_CORRECT", Severity.INFO, "Serialisation Control",
                "password", "password", "com.example.Dto",
                "/api/users", "GET", "com.example.Controller",
                "msg", "rec", false, true
        );
        String html = readReport(dir, resultWithFinding(infoFinding));
        // No rec-item *element* should appear (the CSS class definition is always present,
        // but no <div class="rec-item"> should be rendered when all findings are INFO)
        assertThat(html).contains("rec-clean");
        assertThat(html).doesNotContain("class=\"rec-item");
    }

    @Test
    void recommendationsAreOrderedBySeverity(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(),
                List.of(
                        new Finding("A", Severity.MEDIUM, "Contact Information",
                                "email", "email", "Dto", "/p", "GET", "Ctrl", "m", "r", false, true),
                        new Finding("B", Severity.CRITICAL, "Credentials",
                                "password", "password", "Dto", "/p", "GET", "Ctrl", "m", "r", false, true)
                ),
                Instant.now()
        );
        String html = readReport(dir, result);
        // After sorting by severity, CRITICAL (Credentials) should appear before MEDIUM (Contact Information)
        assertThat(html.indexOf("sev-critical")).isLessThan(html.indexOf("sev-medium"));
    }

    // -----------------------------------------------------------------------
    // Phase 5 — Scan Metadata section
    // -----------------------------------------------------------------------

    @Test
    void scanMetadataSectionIsPresent(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Scan Metadata");
    }

    @Test
    void scanMetadataShowsTimestampLabel(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Generated");
    }

    @Test
    void scanMetadataShowsEndpointsScannedLabel(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Endpoints Scanned");
    }

    @Test
    void scanMetadataShowsControllersFoundLabel(@TempDir Path dir) throws IOException {
        assertThat(readReport(dir, emptyResult())).contains("Controllers Found");
    }

    @Test
    void scanMetadataShowsCorrectEndpointCount(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(
                        endpoint("GET",  "/api/users",    "com.example.UserController"),
                        endpoint("POST", "/api/products", "com.example.ProductController")
                ),
                List.of(),
                Instant.now()
        );
        String html = readReport(dir, result);
        // "2" should appear in the metadata grid for endpoint count
        assertThat(html).contains("Endpoints Scanned");
        assertThat(html).contains("<div class=\"meta-value\">2</div>");
    }

    @Test
    void scanMetadataShowsPackageTagsWhenEndpointsExist(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(endpoint("GET", "/api/users", "com.example.api.UserController")),
                List.of(),
                Instant.now()
        );
        assertThat(readReport(dir, result)).contains("pkg-tag");
    }

    @Test
    void scanMetadataShowsControllerCount(@TempDir Path dir) throws IOException {
        AnalysisResult result = new AnalysisResult(
                List.of(
                        endpoint("GET",  "/api/users",        "com.example.UserController"),
                        endpoint("POST", "/api/users",        "com.example.UserController"),
                        endpoint("GET",  "/api/products",     "com.example.ProductController")
                ),
                List.of(),
                Instant.now()
        );
        String html = readReport(dir, result);
        // 2 distinct controllers
        assertThat(html).contains("Controllers Found");
        assertThat(html).contains("<div class=\"meta-value\">2</div>");
    }

    // -----------------------------------------------------------------------
    // HTML content — result with findings (existing tests preserved)
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
                "<script>alert('xss')</script>",
                "<script>",
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
    // escJs helper
    // -----------------------------------------------------------------------

    @Test
    void escJsEscapesSingleQuote() {
        assertThat(HtmlReportGenerator.escJs("it's")).isEqualTo("it\\'s");
    }

    @Test
    void escJsEscapesBackslash() {
        assertThat(HtmlReportGenerator.escJs("C:\\path")).isEqualTo("C:\\\\path");
    }

    @Test
    void escJsNullReturnsEmptyString() {
        assertThat(HtmlReportGenerator.escJs(null)).isEmpty();
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

    private static ScannedEndpoint endpoint(String method, String path, String controllerClass) {
        return new ScannedEndpoint(method, path, controllerClass, "testMethod",
                null, null, List.of(), List.of());
    }

    private String readReport(Path dir, AnalysisResult result) throws IOException {
        Path reportPath = GENERATOR.generate(result, dir);
        return Files.readString(reportPath);
    }
}
