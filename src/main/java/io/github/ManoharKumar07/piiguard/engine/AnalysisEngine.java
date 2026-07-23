package io.github.ManoharKumar07.piiguard.engine;

import io.github.ManoharKumar07.piiguard.config.PiiGuardConfiguration;
import io.github.ManoharKumar07.piiguard.model.DtoInfo;
import io.github.ManoharKumar07.piiguard.model.FieldInfo;
import io.github.ManoharKumar07.piiguard.model.ScannedEndpoint;
import io.github.ManoharKumar07.piiguard.rules.AnnotationRule;
import io.github.ManoharKumar07.piiguard.rules.PiiDetectionRule;
import io.github.ManoharKumar07.piiguard.rules.RuleRegistry;
import io.github.ManoharKumar07.piiguard.scan.ClasspathScanner;
import io.github.ManoharKumar07.piiguard.scan.DtoFieldExtractor;
import io.github.ManoharKumar07.piiguard.scan.EndpointAnalyzer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates the full PII Guard analysis pipeline:
 * <ol>
 *   <li>Scan the classpath for {@code @RestController} classes</li>
 *   <li>Extract endpoint metadata (paths, HTTP methods, request/response DTOs)</li>
 *   <li>Apply all rules in the {@link RuleRegistry} to every field in every DTO</li>
 *   <li>Return an {@link AnalysisResult} with all findings</li>
 * </ol>
 *
 * <h3>Suppression</h3>
 * Fields annotated with {@code @PiiGuardSuppress} are skipped (or have specific rules
 * skipped) before rule evaluation, so they never appear in the findings list.
 *
 * <h3>@JsonIgnore handling</h3>
 * When a field carries {@code @JsonIgnore}, non-INFO rules are skipped and only the
 * {@link AnnotationRule} for {@code @JsonIgnore} produces an INFO finding, confirming
 * the field is correctly hidden from the API response.
 */
public final class AnalysisEngine {

    private final ClasspathScanner classpathScanner;
    private final EndpointAnalyzer endpointAnalyzer;
    private final RuleRegistry ruleRegistry;

    /**
     * Creates an engine with custom collaborators — useful for unit testing.
     *
     * @param classpathScanner  scanner used to discover {@code @RestController} classes
     * @param endpointAnalyzer  analyzer used to extract endpoint metadata
     * @param ruleRegistry      registry containing the rules to apply
     */
    public AnalysisEngine(ClasspathScanner classpathScanner,
                          EndpointAnalyzer endpointAnalyzer,
                          RuleRegistry ruleRegistry) {
        this.classpathScanner = classpathScanner;
        this.endpointAnalyzer = endpointAnalyzer;
        this.ruleRegistry = ruleRegistry;
    }

    /**
     * Convenience factory that constructs an engine wired with the default
     * {@link RuleRegistry#defaults() rule set} and the supplied configuration.
     *
     * @param config scan configuration
     * @return a ready-to-use engine
     */
    public static AnalysisEngine create(PiiGuardConfiguration config) {
        DtoFieldExtractor extractor = new DtoFieldExtractor();
        return new AnalysisEngine(
                new ClasspathScanner(),
                new EndpointAnalyzer(extractor, config.maxDtoDepth()),
                RuleRegistry.defaults()
        );
    }

    /**
     * Runs the full analysis pipeline.
     *
     * @param config scan configuration (base packages, depth, etc.)
     * @return immutable analysis result
     */
    public AnalysisResult analyze(PiiGuardConfiguration config) {
        // 1. Discover @RestController classes
        List<Class<?>> controllers = classpathScanner.findRestControllers(config.basePackages());

        // 2. Extract endpoints from each controller
        List<ScannedEndpoint> endpoints = new ArrayList<>();
        for (Class<?> controller : controllers) {
            endpoints.addAll(endpointAnalyzer.analyze(controller));
        }

        // 3. Apply rules to every field in every endpoint's DTOs
        List<Finding> findings = new ArrayList<>();
        for (ScannedEndpoint endpoint : endpoints) {
            evaluateEndpoint(endpoint, findings);
        }

        return new AnalysisResult(
                List.copyOf(endpoints),
                List.copyOf(findings),
                Instant.now()
        );
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private void evaluateEndpoint(ScannedEndpoint endpoint, List<Finding> findings) {
        // Collect all fields from both response and request DTOs
        List<FieldContext> fieldContexts = new ArrayList<>();
        flattenDto(endpoint.responseDto(), true, fieldContexts);
        flattenDto(endpoint.requestDto(), false, fieldContexts);

        for (FieldContext ctx : fieldContexts) {
            evaluateField(ctx.field(), endpoint, ctx.dtoClassName(), ctx.isInResponseBody(), findings);
        }
    }

    private void evaluateField(FieldInfo field, ScannedEndpoint endpoint,
                               String dtoClassName, boolean isInResponseBody,
                               List<Finding> findings) {
        // Check suppression: "*" means all rules suppressed for this field
        if (field.suppressedRules().contains("*")) {
            return;
        }

        boolean jsonIgnored = field.annotations().contains("JsonIgnore");

        for (PiiDetectionRule rule : ruleRegistry.rules()) {
            // Skip suppressed rules for this field
            if (field.suppressedRules().contains(rule.ruleId())) {
                continue;
            }

            // If @JsonIgnore is present, only the JSON_IGNORE_CORRECT annotation rule fires;
            // all field-name and other rules are skipped to avoid false positives.
            if (jsonIgnored && !(rule instanceof AnnotationRule && rule.ruleId().equals("JSON_IGNORE_CORRECT"))) {
                continue;
            }

            rule.evaluate(field, endpoint, dtoClassName, isInResponseBody)
                    .ifPresent(findings::add);
        }
    }

    /**
     * Recursively flattens a {@link DtoInfo} tree into a list of {@link FieldContext} entries.
     * Each entry carries the field, its immediate containing DTO class name, and the
     * request/response context.
     */
    private void flattenDto(DtoInfo dto, boolean isInResponseBody, List<FieldContext> result) {
        if (dto == null || dto.fields().isEmpty()) {
            return;
        }
        for (FieldInfo field : dto.fields()) {
            result.add(new FieldContext(field, dto.className(), isInResponseBody));
            if (field.nestedDto() != null) {
                flattenDto(field.nestedDto(), isInResponseBody, result);
            }
        }
    }

    /** Internal carrier: a field plus its direct DTO class and request/response context. */
    private record FieldContext(FieldInfo field, String dtoClassName, boolean isInResponseBody) {}
}
