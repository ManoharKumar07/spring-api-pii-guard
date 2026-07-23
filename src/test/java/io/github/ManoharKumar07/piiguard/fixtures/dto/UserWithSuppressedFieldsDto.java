package io.github.ManoharKumar07.piiguard.fixtures.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.github.ManoharKumar07.piiguard.suppress.PiiGuardSuppress;

/**
 * DTO used to test the suppression mechanism and @JsonIgnore handling.
 */
public class UserWithSuppressedFieldsDto {

    private Long id;

    /**
     * Suppressed: emailNotificationType is not a personal email address —
     * it's an enum-like string indicating notification preference.
     */
    @PiiGuardSuppress(rules = "EMAIL_EXPOSURE", reason = "Notification preference type, not a personal email address")
    private String emailNotificationType;

    /**
     * Suppressed with all rules: legacy internal field, reviewed and confirmed safe.
     */
    @PiiGuardSuppress(reason = "Legacy internal reference code — reviewed by security team, confirmed not PII")
    private String internalRef;

    /**
     * Correctly hidden via @JsonIgnore — should produce an INFO finding only.
     */
    @JsonIgnore
    private String passwordHash;
}
