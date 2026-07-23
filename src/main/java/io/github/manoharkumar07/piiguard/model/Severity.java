package io.github.manoharkumar07.piiguard.model;

/**
 * Severity levels for PII findings, ordered from most to least critical.
 */
public enum Severity {
    /** Passwords, tokens, private keys exposed in API responses. */
    CRITICAL,
    /** SSN, credit card numbers, Aadhaar, and other government/financial IDs in responses. */
    HIGH,
    /** Email, phone number, date of birth, and other personal contact info in responses. */
    MEDIUM,
    /** Potentially sensitive names (e.g., address fields) — may be false positives. */
    LOW,
    /** Informational — field is correctly hidden via {@code @JsonIgnore} or similar. */
    INFO
}
