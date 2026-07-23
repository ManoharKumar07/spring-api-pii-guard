package io.github.manoharkumar07.piiguard.extension;

import io.github.manoharkumar07.piiguard.config.PiiGuardConfiguration;
import io.github.manoharkumar07.piiguard.engine.AnalysisEngine;
import io.github.manoharkumar07.piiguard.engine.AnalysisResult;
import io.github.manoharkumar07.piiguard.model.Severity;
import io.github.manoharkumar07.piiguard.report.HtmlReportGenerator;
import io.github.manoharkumar07.piiguard.report.ReportGenerator;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ScanResult;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

/**
 * JUnit 5 extension that automatically scans the application's REST API for PII exposure
 * before any tests run.
 *
 * <h2>Simple usage — {@code @ExtendWith}</h2>
 * <pre>{@code
 * @ExtendWith(PiiGuardExtension.class)
 * class PiiGuardScanTest {
 *     @Test
 *     void scanCompletes() {
 *         // The scan runs in beforeAll. This test always passes unless
 *         // failOnFindings is true and findings exceed the minimum severity.
 *     }
 * }
 * }</pre>
 *
 * <h2>Advanced usage — {@code @RegisterExtension}</h2>
 * <pre>{@code
 * class PiiGuardScanTest {
 *
 *     @RegisterExtension
 *     static PiiGuardExtension piiGuard = new PiiGuardExtension(
 *         PiiGuardConfiguration.builder()
 *             .basePackages("com.example.api")
 *             .failOnFindings(true)
 *             .minimumSeverity(Severity.HIGH)
 *             .reportOutputDirectory(Path.of("target/pii-guard"))
 *             .build()
 *     );
 *
 *     @Test
 *     void noCriticalFindings(ExtensionContext context) {
 *         AnalysisResult result = PiiGuardExtension.getResult(context);
 *         assertThat(result.countBySeverity(Severity.CRITICAL)).isZero();
 *     }
 * }
 * }</pre>
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li>The scan runs once per test class in {@code beforeAll}.</li>
 *   <li>An HTML report is always written to the configured output directory
 *       regardless of the {@code failOnFindings} setting.</li>
 *   <li>When {@code failOnFindings} is {@code false} (default), findings are logged
 *       but the test continues normally.</li>
 *   <li>When {@code failOnFindings} is {@code true}, a {@link PiiGuardAssertionError}
 *       is thrown if any finding meets or exceeds {@code minimumSeverity}.</li>
 *   <li>The extension is idempotent: if it has already run for the same test class
 *       the second invocation is a no-op.</li>
 * </ul>
 */
public final class PiiGuardExtension implements BeforeAllCallback {

    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(PiiGuardExtension.class);

    private static final String KEY_RESULT      = "result";
    private static final String KEY_REPORT_PATH = "reportPath";

    private static final Logger logger = LoggerFactory.getLogger(PiiGuardExtension.class);

    private final PiiGuardConfiguration configuration;

    /**
     * Cached result from the most recent scan invocation.
     * Set in {@code beforeAll} and readable from test methods via {@link #getLatestResult()}.
     */
    private volatile AnalysisResult latestResult;

    /**
     * Cached report path from the most recent scan invocation.
     * Set in {@code beforeAll} and readable from test methods via {@link #getLatestReportPath()}.
     */
    private volatile Path latestReportPath;

    /**
     * Zero-arg constructor for declarative {@code @ExtendWith} registration.
     * Uses default configuration (auto-detects base packages, {@code failOnFindings=false},
     * report written to {@code target/pii-guard}).
     */
    public PiiGuardExtension() {
        this(PiiGuardConfiguration.builder().build());
    }

    /**
     * Constructor for programmatic {@code @RegisterExtension} registration with
     * a custom {@link PiiGuardConfiguration}.
     *
     * @param configuration the scan configuration to use
     */
    public PiiGuardExtension(PiiGuardConfiguration configuration) {
        this.configuration = configuration;
    }

    // -----------------------------------------------------------------------
    // BeforeAllCallback
    // -----------------------------------------------------------------------

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        // Idempotency: skip if already run for this test class in this JVM session.
        String testClassName = context.getRequiredTestClass().getName();
        ExtensionContext.Store store = context.getRoot().getStore(NAMESPACE);
        if (store.get(resultKey(testClassName)) != null) {
            return;
        }

        // Resolve packages (explicit config takes precedence; fall back to auto-detect).
        List<String> packages = resolveBasePackages();
        PiiGuardConfiguration resolvedConfig = buildResolvedConfig(packages);

        // Run the full analysis pipeline.
        AnalysisEngine engine = AnalysisEngine.create(resolvedConfig);
        AnalysisResult result = engine.analyze(resolvedConfig);

        // Generate the report (always — regardless of failOnFindings).
        ReportGenerator reportGenerator = new HtmlReportGenerator();
        Path reportPath = reportGenerator.generate(result, configuration.reportOutputDirectory());

        // Persist for later access by test methods.
        store.put(resultKey(testClassName), result);
        store.put(reportKey(testClassName), reportPath);
        this.latestResult     = result;
        this.latestReportPath = reportPath;

        // Log summary.
        logger.info("PII Guard scan complete: {} finding(s) — {} critical, {} high, {} medium, {} low, {} info",
                result.totalFindings(),
                result.countBySeverity(Severity.CRITICAL),
                result.countBySeverity(Severity.HIGH),
                result.countBySeverity(Severity.MEDIUM),
                result.countBySeverity(Severity.LOW),
                result.countBySeverity(Severity.INFO));
        logger.info("PII Guard report: {}", reportPath.toAbsolutePath());

        // Optionally fail the test.
        if (configuration.failOnFindings()
                && result.hasFindings(configuration.minimumSeverity())) {
            throw new PiiGuardAssertionError(reportPath, result);
        }
    }

    // -----------------------------------------------------------------------
    // Instance accessors (for @RegisterExtension static field usage)
    // -----------------------------------------------------------------------

    /**
     * Returns the {@link AnalysisResult} from the most recent scan.
     *
     * <p>This is the recommended way to access results in test methods when the extension
     * is declared as a {@code static} {@code @RegisterExtension} field:
     * <pre>{@code
     * @RegisterExtension
     * static PiiGuardExtension piiGuard = new PiiGuardExtension(...);
     *
     * @Test
     * void noCritical() {
     *     assertThat(piiGuard.getLatestResult().countBySeverity(Severity.CRITICAL)).isZero();
     * }
     * }</pre>
     *
     * @return the latest result, or {@code null} if the extension has not yet run
     */
    public AnalysisResult getLatestResult() {
        return latestResult;
    }

    /**
     * Returns the path of the HTML report from the most recent scan.
     *
     * @return the latest report path, or {@code null} if the extension has not yet run
     */
    public Path getLatestReportPath() {
        return latestReportPath;
    }

    // -----------------------------------------------------------------------
    // Static accessors for test methods
    // -----------------------------------------------------------------------

    /**
     * Returns the {@link AnalysisResult} stored by the extension for the test class
     * associated with the given context.
     *
     * <p>Returns {@code null} if the extension has not yet run for this context
     * (i.e., the method was called before {@code beforeAll}).
     *
     * @param context the current JUnit 5 extension context (injectable into test methods)
     * @return the analysis result, or {@code null}
     */
    public static AnalysisResult getResult(ExtensionContext context) {
        String key = resultKey(context.getRequiredTestClass().getName());
        return context.getRoot().getStore(NAMESPACE).get(key, AnalysisResult.class);
    }

    /**
     * Returns the path to the generated HTML report for the test class associated
     * with the given context.
     *
     * <p>Returns {@code null} if the extension has not yet run for this context.
     *
     * @param context the current JUnit 5 extension context
     * @return the path to the HTML report, or {@code null}
     */
    public static Path getReportPath(ExtensionContext context) {
        String key = reportKey(context.getRequiredTestClass().getName());
        return context.getRoot().getStore(NAMESPACE).get(key, Path.class);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Resolves the base packages to scan.
     *
     * <ol>
     *   <li>If {@link PiiGuardConfiguration#basePackages()} is non-empty, use those.</li>
     *   <li>Otherwise, scan for {@code @SpringBootApplication} and use its package(s).</li>
     *   <li>If still nothing found, fall back to scanning all packages (with a warning).</li>
     * </ol>
     */
    private List<String> resolveBasePackages() {
        if (!configuration.basePackages().isEmpty()) {
            return configuration.basePackages();
        }

        // Auto-detect from @SpringBootApplication.
        try (ScanResult scan = new ClassGraph()
                .enableAnnotationInfo()
                .scan()) {
            List<String> detected = scan
                    .getClassesWithAnnotation(
                            "org.springframework.boot.autoconfigure.SpringBootApplication")
                    .stream()
                    .map(info -> info.getPackageName())
                    .distinct()
                    .toList();

            if (!detected.isEmpty()) {
                logger.info("PII Guard: auto-detected base package(s) from @SpringBootApplication: {}",
                        detected);
                return detected;
            }
        } catch (Exception e) {
            logger.warn("PII Guard: failed to auto-detect @SpringBootApplication: {}", e.getMessage());
        }

        logger.warn("PII Guard: no base packages configured and @SpringBootApplication not found. "
                + "Scanning all packages — this may be slow.");
        return List.of("");
    }

    /**
     * Returns a config identical to {@link #configuration} but with the resolved packages
     * substituted in, so the engine always receives an explicit package list.
     */
    private PiiGuardConfiguration buildResolvedConfig(List<String> packages) {
        if (packages.equals(configuration.basePackages())) {
            return configuration;
        }
        return PiiGuardConfiguration.builder()
                .basePackages(packages)
                .failOnFindings(configuration.failOnFindings())
                .minimumSeverity(configuration.minimumSeverity())
                .reportOutputDirectory(configuration.reportOutputDirectory())
                .maxDtoDepth(configuration.maxDtoDepth())
                .build();
    }

    private static String resultKey(String testClassName) {
        return KEY_RESULT + ":" + testClassName;
    }

    private static String reportKey(String testClassName) {
        return KEY_REPORT_PATH + ":" + testClassName;
    }
}
