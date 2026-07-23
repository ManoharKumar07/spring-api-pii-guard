package io.github.ManoharKumar07.piiguard.extension;

import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;
import io.github.ManoharKumar07.piiguard.engine.Finding;

import java.nio.file.Path;

/**
 * Thrown by {@link PiiGuardExtension} when {@code failOnFindings} is {@code true} and
 * the scan produces at least one finding at or above the configured minimum severity.
 *
 * <h2>Reading the error</h2>
 * <p>The exception message lists every finding in a compact, readable format so that
 * developers can see what triggered the failure directly in the test output — without
 * having to open the HTML report. The full report path is appended at the end.
 *
 * <h2>Catching the error</h2>
 * <p>Consumer tests that want to inspect findings programmatically can catch this error:
 * <pre>{@code
 * try {
 *     // test with failOnFindings=true
 * } catch (PiiGuardAssertionError e) {
 *     AnalysisResult result = e.getResult();
 *     // custom assertions on result.findings() …
 * }
 * }</pre>
 */
public final class PiiGuardAssertionError extends AssertionError {

    private final AnalysisResult result;
    private final Path reportPath;

    /**
     * Creates a new error with a human-readable summary of all findings.
     *
     * @param reportPath path to the generated HTML report
     * @param result     the full analysis result that triggered this error
     */
    public PiiGuardAssertionError(Path reportPath, AnalysisResult result) {
        super(buildMessage(result, reportPath));
        this.result = result;
        this.reportPath = reportPath;
    }

    /** Returns the full analysis result that triggered this error. */
    public AnalysisResult getResult() {
        return result;
    }

    /** Returns the path to the generated HTML report. */
    public Path getReportPath() {
        return reportPath;
    }

    // -----------------------------------------------------------------------

    private static String buildMessage(AnalysisResult result, Path reportPath) {
        StringBuilder sb = new StringBuilder();
        sb.append("PII Guard found ")
          .append(result.totalFindings())
          .append(" potential sensitive data exposure issue(s):\n\n");

        for (Finding f : result.findings()) {
            sb.append(String.format("  [%s] %s — field '%s' in %s %s (DTO: %s)%n",
                    f.severity(),
                    f.ruleId(),
                    f.fieldName(),
                    f.httpMethod(),
                    f.endpointPath(),
                    simpleClass(f.dtoClassName())));
        }

        sb.append("\nSee full report: ").append(reportPath.toAbsolutePath());
        return sb.toString();
    }

    private static String simpleClass(String fqn) {
        if (fqn == null || fqn.isBlank()) {
            return "";
        }
        int dot = fqn.lastIndexOf('.');
        return dot >= 0 ? fqn.substring(dot + 1) : fqn;
    }
}
