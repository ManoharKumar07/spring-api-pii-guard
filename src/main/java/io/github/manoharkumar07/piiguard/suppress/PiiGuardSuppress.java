package io.github.manoharkumar07.piiguard.suppress;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Suppresses one or more PII Guard rule findings on the annotated element.
 *
 * <p>Apply to a field to silence known false positives and document the reason:
 * <pre>{@code
 * @PiiGuardSuppress(rules = "EMAIL_EXPOSURE", reason = "Notification type enum, not a personal email")
 * private String emailNotificationType;
 * }</pre>
 *
 * <p>Omitting {@code rules} suppresses <em>all</em> rules for the annotated field:
 * <pre>{@code
 * @PiiGuardSuppress(reason = "Legacy field, safe to expose")
 * private String legacyToken;
 * }</pre>
 *
 * <p>The {@code reason} attribute is required and must contain a non-empty explanation.
 * This forces developers to document <em>why</em> the finding is a false positive.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.TYPE})
public @interface PiiGuardSuppress {

    /**
     * Rule IDs to suppress (e.g. {@code "EMAIL_EXPOSURE"}, {@code "PHONE_EXPOSURE"}).
     * An empty array suppresses all rules for the annotated element.
     */
    String[] rules() default {};

    /**
     * Mandatory explanation of why this finding is a false positive.
     * Must not be empty.
     */
    String reason();
}
