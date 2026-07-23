package io.github.manoharkumar07.piiguard.report;

import io.github.manoharkumar07.piiguard.engine.AnalysisResult;
import io.github.manoharkumar07.piiguard.engine.Finding;
import io.github.manoharkumar07.piiguard.model.DtoInfo;
import io.github.manoharkumar07.piiguard.model.FieldInfo;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates a self-contained, interactive HTML report from an {@link AnalysisResult}.
 *
 * <p>The report is written to a single {@code .html} file with all CSS and JavaScript
 * embedded inline — no external CDN, stylesheet, or script references — so it can be
 * opened directly from the filesystem, shared via email, or archived without losing
 * fidelity.
 *
 * <h2>Report sections</h2>
 * <ol>
 *   <li><b>Header</b> — library name and scan timestamp</li>
 *   <li><b>Executive Summary</b> — severity-breakdown stat cards and overall status banner</li>
 *   <li><b>Findings</b> — interactive table with severity filter buttons, text search,
 *       and per-row copy-to-clipboard support; sorted CRITICAL → INFO</li>
 *   <li><b>Endpoint Inventory</b> — all scanned endpoints with collapsible DTO field details</li>
 *   <li><b>Recommendations</b> — actionable guidance grouped by PII category and severity</li>
 *   <li><b>Scan Metadata</b> — timestamp, endpoint count, controllers discovered, packages</li>
 * </ol>
 */
public final class HtmlReportGenerator implements ReportGenerator {

    /** Name of the generated report file. */
    static final String REPORT_FILE_NAME = "pii-guard-report.html";

    private static final DateTimeFormatter TIMESTAMP_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
                    .withZone(ZoneId.systemDefault());

    // -----------------------------------------------------------------------
    // Recommendation advice per PII category
    // -----------------------------------------------------------------------

    private static final Map<String, List<String>> CATEGORY_ADVICE;
    static {
        Map<String, List<String>> m = new LinkedHashMap<>();
        m.put("Credentials", List.of(
                "Remove password, secret, token, and API key fields from response DTOs.",
                "Annotate sensitive fields with @JsonIgnore to prevent JSON serialisation.",
                "Use separate request and response DTOs — request DTOs carry credentials, response DTOs do not.",
                "Store only hashed passwords (bcrypt/argon2); never return them in any form."
        ));
        m.put("Government ID", List.of(
                "Social Security Numbers, Aadhaar numbers, and other national IDs must not appear in API responses.",
                "If a reference is necessary, return only a masked form (e.g. ***-**-1234 for SSN).",
                "Store and transmit government IDs only over encrypted channels with strict access controls."
        ));
        m.put("Financial", List.of(
                "PCI-DSS prohibits returning full card numbers or CVV codes — return only the last 4 digits or a token.",
                "Bank account and routing numbers are sensitive financial PII; mask or tokenise them.",
                "Salary and income data requires field-level authorisation — scope access to roles that truly need it."
        ));
        m.put("Contact Information", List.of(
                "Evaluate whether email and phone numbers are necessary in each specific response.",
                "Consider returning masked values (e.g. u***@example.com) where display is needed.",
                "Apply data minimisation: expose contact data only to authorised roles."
        ));
        m.put("Personal Information", List.of(
                "Date of birth, gender, and ethnicity are protected attributes under GDPR and similar laws.",
                "Expose only if strictly required; consider returning age ranges instead of exact dates of birth.",
                "Ensure explicit consent and a lawful basis before exposing special-category personal data."
        ));
        m.put("Health Data", List.of(
                "Medical records and health data are regulated under HIPAA, GDPR, and similar frameworks.",
                "Ensure access is restricted to authenticated, authorised medical personnel.",
                "Apply field-level encryption and audit logging for all health data access."
        ));
        m.put("Biometric Data", List.of(
                "Biometric data (fingerprints, facial recognition, iris scans) is highly sensitive and irreplaceable.",
                "Never transmit raw biometric data over an API — use tokenised references only.",
                "Implement strong authorisation, rate limiting, and audit logging on biometric endpoints."
        ));
        m.put("Location", List.of(
                "Physical addresses and GPS coordinates can be used to track individuals.",
                "Reduce precision when exact location is not required (e.g. city-level instead of street address).",
                "Confirm that location data exposure is necessary and appropriately access-controlled."
        ));
        m.put("Network", List.of(
                "IP addresses are personal data under GDPR in most jurisdictions.",
                "Confirm that exposing IP addresses is necessary and document the lawful basis.",
                "Apply appropriate log retention and anonymisation policies."
        ));
        CATEGORY_ADVICE = Collections.unmodifiableMap(m);
    }

    // -----------------------------------------------------------------------
    // ReportGenerator implementation
    // -----------------------------------------------------------------------

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
                .sorted(java.util.Comparator.comparingInt(f -> f.severity().ordinal()))
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
                + buildRecommendationsSection(sorted)
                + buildScanMetadataSection(result)
                + "</div>\n"
                + "<script>" + JS + "</script>\n"
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
        int total    = result.totalFindings();
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

    // -----------------------------------------------------------------------
    // Findings section — with filter bar, search, and copy buttons
    // -----------------------------------------------------------------------

    private String buildFindingsSection(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Findings (").append(findings.size()).append(")</h2>\n");

        if (findings.isEmpty()) {
            sb.append("  <div class=\"no-findings\">No PII exposure issues detected. Great job!</div>\n");
            sb.append("</section>\n");
            return sb.toString();
        }

        // Count per severity for the filter buttons
        long critical = findings.stream().filter(f -> f.severity() == Severity.CRITICAL).count();
        long high     = findings.stream().filter(f -> f.severity() == Severity.HIGH).count();
        long medium   = findings.stream().filter(f -> f.severity() == Severity.MEDIUM).count();
        long low      = findings.stream().filter(f -> f.severity() == Severity.LOW).count();
        long info     = findings.stream().filter(f -> f.severity() == Severity.INFO).count();

        // Filter bar
        sb.append("  <div class=\"filter-bar\">\n");
        sb.append("    <span class=\"filter-label\">Filter:</span>\n");
        sb.append(filterBtn("all",      "All (" + findings.size() + ")", true,  ""));
        sb.append(filterBtn("critical", "Critical (" + critical + ")",   false, "filter-critical"));
        sb.append(filterBtn("high",     "High (" + high + ")",           false, "filter-high"));
        sb.append(filterBtn("medium",   "Medium (" + medium + ")",       false, "filter-medium"));
        sb.append(filterBtn("low",      "Low (" + low + ")",             false, "filter-low"));
        sb.append(filterBtn("info",     "Info (" + info + ")",           false, "filter-info"));
        sb.append("    <input type=\"text\" id=\"findings-search\" class=\"search-input\""
                + " placeholder=\"Search field, endpoint, DTO\u2026\" oninput=\"applyFilters()\">\n");
        sb.append("  </div>\n");

        // Findings table
        sb.append("  <div class=\"table-wrapper\">\n");
        sb.append("  <table id=\"findings-table\">\n");
        sb.append("    <thead><tr>")
          .append("<th>Severity</th>")
          .append("<th>Rule ID</th>")
          .append("<th>Field</th>")
          .append("<th>Endpoint</th>")
          .append("<th>DTO</th>")
          .append("<th>Location</th>")
          .append("<th>Recommendation</th>")
          .append("<th></th>")
          .append("</tr></thead>\n");
        sb.append("    <tbody>\n");

        for (Finding f : findings) {
            String location  = f.isInResponseBody() ? "Response Body" : "Request Body";
            // Build the copy-to-clipboard text and HTML-escape it for the data attribute.
            // The browser automatically decodes HTML entities when reading dataset.copy in JS,
            // so the user receives the original unescaped text on the clipboard.
            String copyText  = esc("[" + f.severity().name() + "] " + f.ruleId()
                    + " | " + f.fieldName()
                    + " | " + f.httpMethod() + " " + f.endpointPath()
                    + " | " + simpleClass(f.dtoClassName()));

            sb.append("    <tr data-severity=\"").append(f.severity().name().toLowerCase()).append("\">")
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
              .append("<td><button class=\"copy-btn\" data-copy=\"")
                  .append(copyText).append("\" onclick=\"copyFinding(this)\">Copy</button></td>")
              .append("</tr>\n");
        }

        sb.append("    </tbody>\n");
        sb.append("  </table>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");
        return sb.toString();
    }

    private static String filterBtn(String sev, String label, boolean active, String extraClass) {
        String cls = "filter-btn" + (extraClass.isEmpty() ? "" : " " + extraClass) + (active ? " active" : "");
        return "    <button class=\"" + cls + "\" data-severity=\"" + sev
                + "\" onclick=\"setSeverityFilter(this,'" + sev + "')\">"
                + esc(label) + "</button>\n";
    }

    // -----------------------------------------------------------------------
    // Endpoint inventory — with collapsible DTO detail rows
    // -----------------------------------------------------------------------

    private String buildEndpointsSection(List<ScannedEndpoint> endpoints) {
        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Scanned Endpoints (").append(endpoints.size()).append(")</h2>\n");

        if (endpoints.isEmpty()) {
            sb.append("  <p>No endpoints were discovered.</p>\n");
            sb.append("</section>\n");
            return sb.toString();
        }

        sb.append("  <p class=\"hint\">Click a row to expand DTO field details.</p>\n");
        sb.append("  <div class=\"table-wrapper\">\n");
        sb.append("  <table>\n");
        sb.append("    <thead><tr>")
          .append("<th></th>")
          .append("<th>Method</th>")
          .append("<th>Path</th>")
          .append("<th>Controller</th>")
          .append("<th>Request DTO</th>")
          .append("<th>Response DTO</th>")
          .append("</tr></thead>\n");
        sb.append("    <tbody>\n");

        for (ScannedEndpoint ep : endpoints) {
            String reqDto  = ep.requestDto()  != null ? simpleClass(ep.requestDto().className())  : "\u2014";
            String respDto = ep.responseDto() != null ? simpleClass(ep.responseDto().className()) : "\u2014";

            // Primary (clickable) row
            sb.append("    <tr class=\"ep-row\" onclick=\"toggleEp(this)\">")
              .append("<td><span class=\"expand-icon\">\u25b6</span></td>")
              .append("<td><span class=\"method\">").append(esc(ep.httpMethod())).append("</span></td>")
              .append("<td class=\"mono\">").append(esc(ep.path())).append("</td>")
              .append("<td class=\"mono small\">").append(esc(simpleClass(ep.controllerClass()))).append("</td>")
              .append("<td class=\"mono small\">").append(esc(reqDto)).append("</td>")
              .append("<td class=\"mono small\">").append(esc(respDto)).append("</td>")
              .append("</tr>\n");

            // Hidden detail row
            sb.append("    <tr class=\"ep-detail\" style=\"display:none\"><td colspan=\"6\">\n");
            sb.append("      <div class=\"dto-grid\">\n");
            sb.append(dtoDetailBlock("Request Body",  ep.requestDto()));
            sb.append(dtoDetailBlock("Response Body", ep.responseDto()));
            sb.append("      </div>\n");
            sb.append("    </td></tr>\n");
        }

        sb.append("    </tbody>\n");
        sb.append("  </table>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");
        return sb.toString();
    }

    private static String dtoDetailBlock(String label, DtoInfo dto) {
        StringBuilder sb = new StringBuilder();
        sb.append("        <div class=\"dto-block\">\n");
        sb.append("          <div class=\"dto-label\">").append(esc(label)).append("</div>\n");
        if (dto == null) {
            sb.append("          <div class=\"dto-fields none\">\u2014</div>\n");
        } else {
            sb.append("          <div class=\"dto-fields\">").append(esc(simpleClass(dto.className()))).append("</div>\n");
            if (!dto.fields().isEmpty()) {
                sb.append("          <div class=\"dto-field-list\">\n");
                for (FieldInfo field : dto.fields()) {
                    sb.append("            <span class=\"dto-field-item\">")
                      .append(esc(field.name())).append(": ")
                      .append(esc(field.typeName()))
                      .append("</span>\n");
                }
                sb.append("          </div>\n");
            }
        }
        sb.append("        </div>\n");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Recommendations section — grouped by PII category
    // -----------------------------------------------------------------------

    private String buildRecommendationsSection(List<Finding> findings) {
        // Collect unique categories (excluding INFO) in severity order — findings are already sorted
        Map<String, Severity> categoryToSeverity = new LinkedHashMap<>();
        for (Finding f : findings) {
            if (f.severity() != Severity.INFO) {
                categoryToSeverity.putIfAbsent(f.piiCategory(), f.severity());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Recommendations</h2>\n");

        if (categoryToSeverity.isEmpty()) {
            sb.append("  <div class=\"rec-clean\">No issues to address — your API handles PII responsibly.</div>\n");
            sb.append("</section>\n");
            return sb.toString();
        }

        for (Map.Entry<String, Severity> entry : categoryToSeverity.entrySet()) {
            String category = entry.getKey();
            Severity sev    = entry.getValue();
            String sevClass = "sev-" + sev.name().toLowerCase();

            List<String> advice = CATEGORY_ADVICE.getOrDefault(category, List.of(
                    "Review and remove or mask this field from the API response.",
                    "Annotate with @JsonIgnore if the field must exist in the DTO but should not be serialised.",
                    "Consult your data protection policy for handling of " + category + " data."
            ));

            sb.append("  <div class=\"rec-item ").append(sevClass).append("\">\n");
            sb.append("    <div class=\"rec-category\">")
              .append("<span class=\"badge severity-").append(sev.name().toLowerCase())
              .append("\">").append(esc(sev.name())).append("</span> ")
              .append(esc(category))
              .append("</div>\n");
            sb.append("    <div class=\"rec-advice\"><ul>\n");
            for (String point : advice) {
                sb.append("      <li>").append(esc(point)).append("</li>\n");
            }
            sb.append("    </ul></div>\n");
            sb.append("  </div>\n");
        }

        sb.append("</section>\n");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Scan metadata section
    // -----------------------------------------------------------------------

    private String buildScanMetadataSection(AnalysisResult result) {
        List<ScannedEndpoint> endpoints = result.endpoints();

        long controllerCount = endpoints.stream()
                .map(ScannedEndpoint::controllerClass)
                .distinct()
                .count();

        List<String> packages = endpoints.stream()
                .map(e -> packageOf(e.controllerClass()))
                .distinct()
                .sorted()
                .toList();

        StringBuilder sb = new StringBuilder();
        sb.append("<section class=\"section\">\n");
        sb.append("  <h2>Scan Metadata</h2>\n");
        sb.append("  <div class=\"meta-grid\">\n");
        sb.append(metaItem("Generated",          TIMESTAMP_FMT.format(result.timestamp())));
        sb.append(metaItem("Endpoints Scanned",  String.valueOf(endpoints.size())));
        sb.append(metaItem("Controllers Found",  String.valueOf(controllerCount)));
        sb.append(metaItem("Total Findings",     String.valueOf(result.totalFindings())));
        sb.append("  </div>\n");

        if (!packages.isEmpty()) {
            sb.append("  <div class=\"meta-packages\"><strong>Packages scanned:&nbsp;</strong>\n");
            for (String pkg : packages) {
                sb.append("    <span class=\"pkg-tag\">").append(esc(pkg)).append("</span>\n");
            }
            sb.append("  </div>\n");
        }

        sb.append("</section>\n");
        return sb.toString();
    }

    private static String metaItem(String key, String value) {
        return "    <div class=\"meta-item\">"
                + "<div class=\"meta-key\">" + esc(key) + "</div>"
                + "<div class=\"meta-value\">" + esc(value) + "</div>"
                + "</div>\n";
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    /** Returns the simple (unqualified) class name from a fully-qualified name. */
    private static String simpleClass(String fqn) {
        if (fqn == null || fqn.isBlank()) return "";
        int dot = fqn.lastIndexOf('.');
        return dot >= 0 ? fqn.substring(dot + 1) : fqn;
    }

    /** Returns the package portion of a fully-qualified class name. */
    private static String packageOf(String fqn) {
        if (fqn == null || fqn.isBlank()) return "(default)";
        int dot = fqn.lastIndexOf('.');
        return dot > 0 ? fqn.substring(0, dot) : "(default)";
    }

    /**
     * HTML-escapes a string to prevent content injection.
     * Package-private for unit testing.
     */
    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /**
     * Escapes a string for embedding inside a single-quoted JavaScript string literal.
     * Package-private for unit testing.
     */
    static String escJs(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("'", "\\'");
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
            .hint{font-size:.82rem;color:#64748b;margin:0 0 12px}
            .filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px}
            .filter-label{font-size:.8rem;color:#64748b;font-weight:600;white-space:nowrap}
            .filter-btn{padding:4px 12px;border:1px solid #cbd5e1;border-radius:20px;cursor:pointer;font-size:.78rem;font-weight:600;background:white;color:#64748b;transition:background .15s,color .15s,border-color .15s}
            .filter-btn:hover{background:#f1f5f9}
            .filter-btn.active{background:#1e3a5f;color:white;border-color:#1e3a5f}
            .filter-btn.filter-critical.active{background:#dc2626;border-color:#dc2626}
            .filter-btn.filter-high.active{background:#ea580c;border-color:#ea580c}
            .filter-btn.filter-medium.active{background:#ca8a04;border-color:#ca8a04}
            .filter-btn.filter-low.active{background:#2563eb;border-color:#2563eb}
            .filter-btn.filter-info.active{background:#6b7280;border-color:#6b7280}
            .search-input{margin-left:auto;padding:5px 14px;border:1px solid #e2e8f0;border-radius:20px;font-size:.82rem;width:240px;outline:none;font-family:inherit}
            .search-input:focus{border-color:#2d6a9f;box-shadow:0 0 0 2px rgba(45,106,159,.12)}
            .copy-btn{padding:2px 8px;font-size:.7rem;border:1px solid #e2e8f0;border-radius:4px;cursor:pointer;background:white;color:#64748b;white-space:nowrap}
            .copy-btn:hover{background:#f1f5f9;border-color:#cbd5e1}
            .ep-row{cursor:pointer;user-select:none}
            .ep-row:hover td{background:#f0f9ff!important}
            .expand-icon{display:inline-block;font-size:.75rem;color:#94a3b8;transition:transform .2s}
            .ep-detail td{background:#f8fafc;padding:12px 16px}
            .dto-grid{display:flex;gap:24px;flex-wrap:wrap}
            .dto-block{flex:1;min-width:180px}
            .dto-label{font-size:.72rem;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
            .dto-fields{font-size:.85rem;font-weight:600;color:#1e293b;font-family:'SFMono-Regular',Consolas,monospace}
            .dto-fields.none{color:#94a3b8;font-weight:400;font-family:inherit}
            .dto-field-list{margin-top:6px}
            .dto-field-item{display:block;font-size:.78rem;color:#64748b;font-family:'SFMono-Regular',Consolas,monospace;line-height:1.7}
            .rec-item{padding:16px;border-radius:6px;margin-bottom:12px;border-left:4px solid transparent}
            .rec-item.sev-critical{border-color:#dc2626;background:#fef2f2}
            .rec-item.sev-high{border-color:#ea580c;background:#fff7ed}
            .rec-item.sev-medium{border-color:#ca8a04;background:#fefce8}
            .rec-item.sev-low{border-color:#2563eb;background:#eff6ff}
            .rec-item.sev-info{border-color:#6b7280;background:#f8fafc}
            .rec-category{font-weight:700;font-size:.9rem;margin-bottom:8px}
            .rec-advice{font-size:.875rem;color:#374151;line-height:1.6}
            .rec-advice ul{margin:0;padding-left:20px}
            .rec-advice li{margin-bottom:4px}
            .rec-clean{text-align:center;padding:24px;background:#dcfce7;border-radius:6px;color:#15803d;font-weight:500}
            .meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:12px}
            .meta-item{background:#f8fafc;border-radius:6px;padding:14px}
            .meta-key{font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;font-weight:600}
            .meta-value{font-size:.92rem;font-weight:600;color:#1e293b;word-break:break-all}
            .meta-packages{font-size:.82rem;color:#64748b;margin-top:4px}
            .pkg-tag{display:inline-block;background:#e2e8f0;border-radius:4px;padding:2px 8px;margin:2px 4px 2px 0;font-family:'SFMono-Regular',Consolas,monospace;font-size:.78rem;color:#374151}
            """;

    // -----------------------------------------------------------------------
    // Embedded JavaScript — no external dependencies, works offline
    // -----------------------------------------------------------------------

    private static final String JS = """
            function setSeverityFilter(btn,sev){
              [].forEach.call(document.querySelectorAll('.filter-btn'),function(b){b.classList.remove('active');});
              btn.classList.add('active');
              applyFilters();
            }
            function applyFilters(){
              var a=document.querySelector('.filter-btn.active');
              var sev=a?a.dataset.severity:'all';
              var el=document.getElementById('findings-search');
              var q=el?el.value.toLowerCase():'';
              [].forEach.call(document.querySelectorAll('#findings-table tbody tr'),function(row){
                var ms=sev==='all'||row.dataset.severity===sev;
                var mq=!q||row.textContent.toLowerCase().indexOf(q)>=0;
                row.style.display=(ms&&mq)?'':'none';
              });
            }
            function toggleEp(row){
              var next=row.nextElementSibling;
              if(next&&next.classList.contains('ep-detail')){
                var hide=next.style.display!=='none';
                next.style.display=hide?'none':'';
                var ic=row.querySelector('.expand-icon');
                if(ic)ic.textContent=hide?'\u25b6':'\u25bc';
              }
            }
            function copyFinding(btn){
              function done(){var o=btn.textContent;btn.textContent='\u2713 Copied';setTimeout(function(){btn.textContent=o;},2000);}
              var text=btn.dataset.copy||'';
              if(window.navigator&&navigator.clipboard){
                navigator.clipboard.writeText(text).then(done,function(){done();});
              }else{
                var t=document.createElement('textarea');
                t.value=text;t.style.position='fixed';t.style.opacity='0';
                document.body.appendChild(t);t.select();
                try{document.execCommand('copy');}catch(e){}
                document.body.removeChild(t);done();
              }
            }
            """;
}
