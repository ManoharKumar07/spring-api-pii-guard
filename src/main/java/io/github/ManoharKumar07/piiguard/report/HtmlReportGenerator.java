package io.github.ManoharKumar07.piiguard.report;

import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;
import io.github.ManoharKumar07.piiguard.engine.Finding;
import io.github.ManoharKumar07.piiguard.model.ScannedEndpoint;
import io.github.ManoharKumar07.piiguard.model.Severity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

/**
 * Generates a self-contained HTML report from an {@link AnalysisResult}.
 *
 * <p>The report is written to a single {@code .html} file with all CSS embedded inline
 * (no external CDN or file references), so it can be opened directly from the filesystem,
 * shared via email, or archived without losing fidelity.
 *
 * <h3>Report sections</h3>
 * <ol>
 *   <li>Header — library name and scan timestamp</li>
 *   <li>Executive summary — severity-breakdown stat cards and overall status banner</li>
 *   <li>Findings table — all findings sorted by severity (CRITICAL first)</li>
 *   <li>Endpoint inventory — all scanned endpoints with their request/response DTOs</li>
 * </ol>
 *
 * <p>Phase 5 will extend this class with interactive JavaScript filters, search, and
 * a richer visual design.
 */
public final class HtmlReportGenerator implements ReportGenerator {

    /** Name of the generated report file. */
    static final String REPORT_FILE_NAME = "pii-guard-report.html";

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                    .withZone(ZoneId.systemDefault());

    @Override
    public Path generate(AnalysisResult result, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);
        Path reportFile = outputDirectory.resolve(REPORT_FILE_NAME);
        Files.writeString(reportFile, buildHtml(result), StandardCharsets.UTF_8);
        return reportFile;
    }

    // -----------------------------------------------------------------------
    // HTML construction
    // -----------------------------------------------------------------------

    /** Builds the complete HTML document. Package-private for unit testing. */
    String buildHtml(AnalysisResult result) {
        List<Finding> sorted = result.findings().stream()
                .sorted(Comparator.comparingInt(f -> f.severity().ordinal()))
                .toList();

        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "<head>\n"
                + "  <meta charset=\"UTF-8\">\n"
                + "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
                + "  <title>PII Guard Report</title>\n"
                + "  <style>" + CSS + "</style>\n"
                + "</head>\n"
                + "<body>\n"
                + buildHeader(result)
                + "<div class=\"container\">\n"
                + buildSummary(result)
                + buildFindingsSection(sorted)
                + buildEndpointsSection(result.endpoints())
                + "</div>\n"
                + "</body>\n"
                + "</html>";
    }

    private String buildHeader(AnalysisResult result) {
        return "<div class=\"header\">\n"
                + "  <h1>Spring API PII Guard</h1>\n"
                + "  <p class=\"subtitle\">Security Scan Report</p>\n"
                + "  <p class=\"timestamp\">Generated: "
                + TIMESTAMP_FMT.format(result.timestamp()) + "</p>\n"
                + "</div>\n";
    }

    private String buildSummary(AnalysisResult result) {
        int total = result.totalFindings();
        long critical = result.countBySeverity(Severity.CRITICAL);
        long high     = result.countBySeverity(Severity.HIGH);
        long medium   = result.countBySeverity(Severity.MEDIUM);
        long low      = result.countBySeverity(Severity.LOW);
        long info     = result.countBySeverity(Severity.INFO);

        String bannerClass = total == 0
                ? "status-clean"
                : (critical > 0 || high > 0) ? "status-danger" : "status-warning";
        String bannerMsg = total == 0
                ? "No PII exposure issues detected — clean scan!"
                : total + " potential PII exposure issue(s) detected";

        return "<section class=\"summary\">\n"
                + "  <h2>Executive Summary</h2>\n"
                + "  <div class=\"status-banner " + bannerClass + "\">" + esc(bannerMsg) + "</div>\n"
                + "  <div class=\"stats-grid\">\n"
                + statCard("severity-critical", critical, "Critical")
                + statCard("severity-high",     high,     "High")
                + statCard("severity-medium",   medium,   "Medium")
                + statCard("severity-low",      low,      "Low")
                + statCard("severity-info",     info,     "Info")
                + statCard("stat-endpoints",    result.endpoints().size(), "Endpoints")
                + "  </div>\n"
                + "</section>\n";
    }

    private static String statCard(String cssClass, long value, String label) {
        return "    <div class=\"stat-card " + cssClass + "\">"
                + "<div class=\"stat-value\">" + value + "</div>"
                + "<div class=\"stat-label\">" + esc(label) + "</div>"
                + "</div>\n";
    }

    private String buildFindingsSection(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Findings (").append(findings.size()).append(")</h2>\n");

        if (findings.isEmpty()) {
            sb.append("  <div class=\"no-findings\">No PII exposure issues detected. Great job!</div>\n");
            sb.append("</section>\n");
            return sb.toString();
        }

        sb.append("  <div class=\"table-wrapper\">\n");
        sb.append("  <table>\n");
        sb.append("    <thead><tr>")
          .append("<th>Severity</th>")
          .append("<th>Rule ID</th>")
          .append("<th>Field</th>")
          .append("<th>Endpoint</th>")
          .append("<th>DTO</th>")
          .append("<th>Location</th>")
          .append("<th>Recommendation</th>")
          .append("</tr></thead>\n");
        sb.append("    <tbody>\n");

        for (Finding f : findings) {
            String location = f.isInResponseBody() ? "Response Body" : "Request Body";
            sb.append("    <tr>")
              .append("<td><span class=\"badge severity-").append(f.severity().name().toLowerCase())
                  .append("\">").append(esc(f.severity().name())).append("</span></td>")
              .append("<td class=\"mono\">").append(esc(f.ruleId())).append("</td>")
              .append("<td class=\"mono\">").append(esc(f.fieldName())).append("</td>")
              .append("<td>")
                  .append("<span class=\"method\">").append(esc(f.httpMethod())).append("</span> ")
                  .append(esc(f.endpointPath()))
                  .append("</td>")
              .append("<td class=\"mono small\">").append(esc(simpleClass(f.dtoClassName()))).append("</td>")
              .append("<td>").append(esc(location)).append("</td>")
              .append("<td class=\"small\">").append(esc(f.recommendation())).append("</td>")
              .append("</tr>\n");
        }

        sb.append("    </tbody>\n");
        sb.append("  </table>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");
        return sb.toString();
    }

    private String buildEndpointsSection(List<ScannedEndpoint> endpoints) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Scanned Endpoints (").append(endpoints.size()).append(")</h2>\n");

        if (endpoints.isEmpty()) {
            sb.append("  <p>No endpoints were discovered.</p>\n");
            sb.append("</section>\n");
            return sb.toString();
        }

        sb.append("  <div class=\"table-wrapper\">\n");
        sb.append("  <table>\n");
        sb.append("    <thead><tr>")
          .append("<th>Method</th>")
          .append("<th>Path</th>")
          .append("<th>Controller</th>")
          .append("<th>Request DTO</th>")
          .append("<th>Response DTO</th>")
          .append("</tr></thead>\n");
        sb.append("    <tbody>\n");

        for (ScannedEndpoint ep : endpoints) {
            String reqDto  = ep.requestDto()  != null ? simpleClass(ep.requestDto().className())  : "—";
            String respDto = ep.responseDto() != null ? simpleClass(ep.responseDto().className()) : "—";
            sb.append("    <tr>")
              .append("<td><span class=\"method\">").append(esc(ep.httpMethod())).append("</span></td>")
              .append("<td class=\"mono\">").append(esc(ep.path())).append("</td>")
              .append("<td class=\"mono small\">").append(esc(simpleClass(ep.controllerClass()))).append("</td>")
              .append("<td class=\"mono small\">").append(esc(reqDto)).append("</td>")
              .append("<td class=\"mono small\">").append(esc(respDto)).append("</td>")
              .append("</tr>\n");
        }

        sb.append("    </tbody>\n");
        sb.append("  </table>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /** Returns the simple (unqualified) class name from a fully-qualified name. */
    private static String simpleClass(String fqn) {
        if (fqn == null || fqn.isBlank()) {
            return "";
        }
        int dot = fqn.lastIndexOf('.');
        return dot >= 0 ? fqn.substring(dot + 1) : fqn;
    }

    /**
     * HTML-escapes a string to prevent content injection.
     * Package-private for unit testing.
     */
    static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    // -----------------------------------------------------------------------
    // Embedded CSS — no external dependencies, works offline
    // -----------------------------------------------------------------------

    private static final String CSS = """
            *,*::before,*::after{box-sizing:border-box}
            body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;background:#f8fafc;color:#1e293b;line-height:1.5}
            .header{background:linear-gradient(135deg,#1e3a5f 0%,#2d6a9f 100%);color:white;padding:32px}
            .header h1{margin:0 0 6px;font-size:2rem;letter-spacing:-.5px}
            .header .subtitle{margin:0;font-size:1.05rem;opacity:.85}
            .header .timestamp{margin:10px 0 0;font-size:.82rem;opacity:.65}
            .container{max-width:1200px;margin:0 auto;padding:28px 24px}
            .summary{margin-bottom:24px}
            .summary h2,.section h2{margin:0 0 16px;color:#1e293b;font-size:1.2rem}
            .status-banner{padding:12px 20px;border-radius:6px;font-weight:600;font-size:1rem;margin-bottom:20px}
            .status-clean{background:#dcfce7;color:#15803d;border-left:5px solid #16a34a}
            .status-warning{background:#fef3c7;color:#92400e;border-left:5px solid #d97706}
            .status-danger{background:#fee2e2;color:#991b1b;border-left:5px solid #dc2626}
            .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
            .stat-card{background:white;border-radius:8px;padding:16px 12px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08);border-top:4px solid #e2e8f0}
            .stat-value{font-size:1.9rem;font-weight:700}
            .stat-label{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px}
            .stat-card.severity-critical{border-top-color:#dc2626}.stat-card.severity-critical .stat-value{color:#dc2626}
            .stat-card.severity-high{border-top-color:#ea580c}.stat-card.severity-high .stat-value{color:#ea580c}
            .stat-card.severity-medium{border-top-color:#ca8a04}.stat-card.severity-medium .stat-value{color:#ca8a04}
            .stat-card.severity-low{border-top-color:#2563eb}.stat-card.severity-low .stat-value{color:#2563eb}
            .stat-card.severity-info{border-top-color:#6b7280}.stat-card.severity-info .stat-value{color:#6b7280}
            .stat-card.stat-endpoints{border-top-color:#7c3aed}.stat-card.stat-endpoints .stat-value{color:#7c3aed}
            .section{background:white;border-radius:8px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
            .no-findings{padding:24px;text-align:center;color:#15803d;background:#dcfce7;border-radius:6px;font-weight:500}
            .table-wrapper{overflow-x:auto}
            table{width:100%;border-collapse:collapse;font-size:.875rem}
            th{background:#f1f5f9;color:#475569;text-align:left;padding:10px 12px;font-weight:600;border-bottom:2px solid #e2e8f0;white-space:nowrap}
            td{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
            tr:last-child td{border-bottom:none}
            tr:hover td{background:#f8fafc}
            .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700;color:white;white-space:nowrap}
            .badge.severity-critical{background:#dc2626}
            .badge.severity-high{background:#ea580c}
            .badge.severity-medium{background:#ca8a04}
            .badge.severity-low{background:#2563eb}
            .badge.severity-info{background:#6b7280}
            .method{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.7rem;font-weight:700;background:#e0f2fe;color:#0369a1;letter-spacing:.02em}
            .mono{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}
            .small{font-size:.82em}
            """;
}
