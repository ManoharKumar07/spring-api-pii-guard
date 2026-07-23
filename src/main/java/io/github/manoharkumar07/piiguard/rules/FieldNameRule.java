package io.github.manoharkumar07.piiguard.rules;

import io.github.manoharkumar07.piiguard.engine.Finding;
import io.github.manoharkumar07.piiguard.model.FieldInfo;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A {@link PiiDetectionRule} that detects PII by matching the normalised field name
 * against a compiled {@link Pattern}.
 *
 * <h2>Normalisation</h2>
 * Before matching, the field's JSON name is normalised:
 * <ol>
 *   <li>camelCase → snake_case (insert underscore before each uppercase letter)</li>
 *   <li>hyphens → underscores</li>
 *   <li>lowercase the result</li>
 * </ol>
 * Pattern matching uses {@link java.util.regex.Matcher#find()} so the pattern only
 * needs to match a substring — e.g., the pattern {@code password} matches
 * {@code password_hash}, {@code confirm_password}, and {@code user_password}.
 *
 * <p>Instances are created via the static factory {@link #of(String, Severity, String, Pattern, String, String)}.
 */
public final class FieldNameRule implements PiiDetectionRule {

    private final String ruleId;
    private final String description;
    private final Severity severity;
    private final Pattern pattern;
    private final String piiCategory;
    private final String recommendation;

    private FieldNameRule(String ruleId, String description, Severity severity,
                          Pattern pattern, String piiCategory, String recommendation) {
        this.ruleId = ruleId;
        this.description = description;
        this.severity = severity;
        this.pattern = pattern;
        this.piiCategory = piiCategory;
        this.recommendation = recommendation;
    }

    /**
     * Creates a {@link FieldNameRule}.
     *
     * @param ruleId         unique rule identifier
     * @param severity       severity of findings produced by this rule
     * @param description    human-readable description of what is detected
     * @param pattern        compiled regex applied to the normalised field JSON name
     * @param piiCategory    PII category label (e.g. "Credentials", "Government ID")
     * @param recommendation actionable fix suggestion included in each finding
     */
    public static FieldNameRule of(String ruleId, Severity severity, String description,
                                   Pattern pattern, String piiCategory, String recommendation) {
        return new FieldNameRule(ruleId, description, severity, pattern, piiCategory, recommendation);
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
        String normalised = normalise(field.jsonName());
        if (!pattern.matcher(normalised).find()) {
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

    /**
     * Normalises a field name for pattern matching.
     * <ul>
     *   <li>{@code socialSecurityNumber} → {@code social_security_number}</li>
     *   <li>{@code passwordHash} → {@code password_hash}</li>
     *   <li>{@code my-field-name} → {@code my_field_name}</li>
     * </ul>
     */
    static String normalise(String name) {
        // Insert underscore before uppercase letters that follow lowercase letters (camelCase split)
        String snaked = name.replaceAll("([a-z])([A-Z])", "$1_$2");
        // Replace hyphens with underscores and lowercase the whole string
        return snaked.replace('-', '_').toLowerCase();
    }
}
