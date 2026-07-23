package io.github.ManoharKumar07.piiguard.rules;

import io.github.ManoharKumar07.piiguard.engine.Finding;
import io.github.ManoharKumar07.piiguard.model.FieldInfo;
import io.github.ManoharKumar07.piiguard.model.ScannedEndpoint;
import io.github.ManoharKumar07.piiguard.model.Severity;

import java.util.Optional;

/**
 * Contract for a single PII detection rule.
 *
 * <p>Implementations must be stateless and thread-safe. Each rule is a pure function:
 * given a field and its context, it either produces a {@link Finding} or returns empty.
 *
 * <p>To create a custom rule, implement this interface and register it with
 * {@link RuleRegistry#withAdditionalRules(java.util.List)}.
 *
 * <h2>Example</h2>
 * <pre>{@code
 * public class MyCustomRule implements PiiDetectionRule {
 *     public String ruleId()      { return "MY_CUSTOM_RULE"; }
 *     public String description() { return "Detects custom sensitive patterns"; }
 *     public Severity severity()  { return Severity.HIGH; }
 *
 *     public Optional<Finding> evaluate(
 *             FieldInfo field, ScannedEndpoint endpoint,
 *             String dtoClassName, boolean isInResponseBody) {
 *         if (field.name().equals("mySecret")) {
 *             return Optional.of(new Finding(...));
 *         }
 *         return Optional.empty();
 *     }
 * }
 * }</pre>
 */
public interface PiiDetectionRule {

    /** Unique identifier for this rule (e.g. {@code "PASSWORD_EXPOSURE"}). */
    String ruleId();

    /** Human-readable explanation of what this rule detects. */
    String description();

    /** Severity level assigned to findings produced by this rule. */
    Severity severity();

    /**
     * Evaluates a single field in the context of its endpoint.
     *
     * @param field            the field to inspect
     * @param endpoint         the endpoint that contains this field's DTO
     * @param dtoClassName     fully qualified name of the DTO class that directly contains {@code field}
     * @param isInResponseBody {@code true} if the field belongs to a response DTO;
     *                         {@code false} if it belongs to a request body DTO
     * @return a populated {@link Finding} if the rule matches, or {@link Optional#empty()} otherwise
     */
    Optional<Finding> evaluate(FieldInfo field, ScannedEndpoint endpoint,
                               String dtoClassName, boolean isInResponseBody);
}
