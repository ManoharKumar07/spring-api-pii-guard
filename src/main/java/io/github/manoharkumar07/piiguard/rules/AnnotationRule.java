package io.github.manoharkumar07.piiguard.rules;

import io.github.manoharkumar07.piiguard.engine.Finding;
import io.github.manoharkumar07.piiguard.model.FieldInfo;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;

import java.util.Optional;

/**
 * A {@link PiiDetectionRule} that detects PII based on annotations present on a field.
 *
 * <p>Supported detections:
 * <ul>
 *   <li>{@code @Email} (Jakarta Validation) — confirms the field contains email data (MEDIUM)</li>
 *   <li>{@code @JsonIgnore} — the field is correctly excluded from serialisation (INFO)</li>
 * </ul>
 *
 * <p>Instances are created via the static factories {@link #forAnnotation} and {@link #forJsonIgnore}.
 */
public final class AnnotationRule implements PiiDetectionRule {

    private final String ruleId;
    private final String description;
    private final Severity severity;
    private final String annotationSimpleName;
    private final String piiCategory;
    private final String recommendation;

    private AnnotationRule(String ruleId, String description, Severity severity,
                           String annotationSimpleName, String piiCategory, String recommendation) {
        this.ruleId = ruleId;
        this.description = description;
        this.severity = severity;
        this.annotationSimpleName = annotationSimpleName;
        this.piiCategory = piiCategory;
        this.recommendation = recommendation;
    }

    /**
     * Creates an {@link AnnotationRule} that fires when the specified annotation is present
     * on the field.
     *
     * @param ruleId               unique rule identifier
     * @param severity             severity of findings produced by this rule
     * @param description          human-readable description
     * @param annotationSimpleName simple name of the annotation to detect (e.g. {@code "Email"})
     * @param piiCategory          PII category label
     * @param recommendation       actionable fix suggestion
     */
    public static AnnotationRule forAnnotation(String ruleId, Severity severity, String description,
                                               String annotationSimpleName, String piiCategory,
                                               String recommendation) {
        return new AnnotationRule(ruleId, description, severity, annotationSimpleName,
                piiCategory, recommendation);
    }

    /**
     * Creates a pre-configured rule that produces an {@link Severity#INFO} finding
     * when a field carries {@code @JsonIgnore}, confirming it is correctly excluded
     * from API responses.
     */
    public static AnnotationRule forJsonIgnore() {
        return new AnnotationRule(
                "JSON_IGNORE_CORRECT",
                "Field is correctly excluded from API responses via @JsonIgnore",
                Severity.INFO,
                "JsonIgnore",
                "Serialisation Control",
                "No action required — @JsonIgnore correctly prevents this field from appearing in responses."
        );
    }

    @Override
    public String ruleId() {
        return ruleId;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public Severity severity() {
        return severity;
    }

    @Override
    public Optional<Finding> evaluate(FieldInfo field, ScannedEndpoint endpoint,
                                      String dtoClassName, boolean isInResponseBody) {
        if (!field.annotations().contains(annotationSimpleName)) {
            return Optional.empty();
        }

        return Optional.of(new Finding(
                ruleId,
                severity,
                piiCategory,
                field.name(),
                field.jsonName(),
                dtoClassName,
                endpoint.path(),
                endpoint.httpMethod(),
                endpoint.controllerClass(),
                description,
                recommendation,
                !isInResponseBody,
                isInResponseBody
        ));
    }
}
