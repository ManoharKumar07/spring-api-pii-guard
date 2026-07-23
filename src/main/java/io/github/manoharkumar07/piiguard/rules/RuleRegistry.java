package io.github.manoharkumar07.piiguard.rules;

import io.github.manoharkumar07.piiguard.model.Severity;
import io.github.manoharkumar07.piiguard.rules.patterns.PiiPatterns;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Holds the ordered list of {@link PiiDetectionRule}s used during analysis.
 *
 * <p>Use {@link #defaults()} to get the standard rule set covering 20+ PII categories.
 * Use {@link #withAdditionalRules(List)} to extend the default set with project-specific rules.
 * Use {@link #of(List)} to build a fully custom registry.
 */
public final class RuleRegistry {

    private final List<PiiDetectionRule> rules;

    private RuleRegistry(List<PiiDetectionRule> rules) {
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
    }

    /** Creates a registry containing only the supplied rules. */
    public static RuleRegistry of(List<PiiDetectionRule> rules) {
        return new RuleRegistry(rules);
    }

    /**
     * Creates a registry with the default rule set — 20+ rules covering credentials,
     * government IDs, financial data, contact info, and location data.
     */
    public static RuleRegistry defaults() {
        return new RuleRegistry(buildDefaultRules());
    }

    /**
     * Creates a registry with the default rules plus additional project-specific rules.
     * Additional rules are appended after the default rules.
     *
     * @param additionalRules rules to append
     * @return a new combined registry
     */
    public RuleRegistry withAdditionalRules(List<PiiDetectionRule> additionalRules) {
        List<PiiDetectionRule> combined = new ArrayList<>(this.rules);
        combined.addAll(additionalRules);
        return new RuleRegistry(combined);
    }

    /** Returns the ordered, immutable list of rules in this registry. */
    public List<PiiDetectionRule> rules() {
        return rules;
    }

    // -----------------------------------------------------------------------
    // Default rule definitions
    // -----------------------------------------------------------------------

    private static List<PiiDetectionRule> buildDefaultRules() {
        List<PiiDetectionRule> rules = new ArrayList<>();

        // ---- CRITICAL: Credentials & Secrets --------------------------------

        rules.add(FieldNameRule.of(
                "PASSWORD_EXPOSURE", Severity.CRITICAL,
                "Password or credential field exposed in API endpoint",
                PiiPatterns.PASSWORD, "Credentials",
                "Remove this field from the DTO or annotate with @JsonIgnore. " +
                        "Never include passwords or password hashes in API responses."));

        rules.add(FieldNameRule.of(
                "SECRET_KEY_EXPOSURE", Severity.CRITICAL,
                "Secret key, API key, or access token exposed in API endpoint",
                PiiPatterns.SECRET_KEY, "Credentials",
                "Remove this field from the DTO or annotate with @JsonIgnore. " +
                        "Tokens and secrets must never appear in API responses."));

        rules.add(FieldNameRule.of(
                "OTP_EXPOSURE", Severity.CRITICAL,
                "One-time password or MFA code exposed in API endpoint",
                PiiPatterns.OTP, "Credentials",
                "OTPs and verification codes must not be returned by the API. " +
                        "Remove this field or annotate with @JsonIgnore."));

        // ---- HIGH: Government IDs -------------------------------------------

        rules.add(FieldNameRule.of(
                "SSN_EXPOSURE", Severity.HIGH,
                "Social Security Number (SSN) exposed in API endpoint",
                PiiPatterns.SSN, "Government ID",
                "SSNs must not appear in API responses. " +
                        "Use a masked representation or remove the field entirely."));

        rules.add(FieldNameRule.of(
                "AADHAAR_EXPOSURE", Severity.HIGH,
                "Aadhaar (Indian national ID) number exposed in API endpoint",
                PiiPatterns.AADHAAR, "Government ID",
                "Aadhaar numbers are regulated under UIDAI guidelines. " +
                        "Mask or remove this field from the API response."));

        rules.add(FieldNameRule.of(
                "NATIONAL_ID_EXPOSURE", Severity.HIGH,
                "Government-issued identity document number exposed in API endpoint",
                PiiPatterns.NATIONAL_ID, "Government ID",
                "National ID, passport, and driving licence numbers are sensitive PII. " +
                        "Remove from the response DTO or apply @JsonIgnore."));

        // ---- HIGH: Financial ------------------------------------------------

        rules.add(FieldNameRule.of(
                "CREDIT_CARD_EXPOSURE", Severity.HIGH,
                "Credit or debit card number exposed in API endpoint",
                PiiPatterns.CREDIT_CARD, "Financial",
                "PCI-DSS prohibits storing or transmitting full card numbers. " +
                        "Return only the last 4 digits or a tokenised reference."));

        rules.add(FieldNameRule.of(
                "CVV_EXPOSURE", Severity.HIGH,
                "Card security code (CVV/CVC) exposed in API endpoint",
                PiiPatterns.CVV, "Financial",
                "CVV/CVC codes must never be stored or returned. " +
                        "Remove this field immediately."));

        rules.add(FieldNameRule.of(
                "BANK_ACCOUNT_EXPOSURE", Severity.HIGH,
                "Bank account or routing number exposed in API endpoint",
                PiiPatterns.BANK_ACCOUNT, "Financial",
                "Bank account numbers are sensitive financial PII. " +
                        "Return only masked values or a tokenised reference."));

        // ---- MEDIUM: Contact Information ------------------------------------

        rules.add(FieldNameRule.of(
                "EMAIL_EXPOSURE", Severity.MEDIUM,
                "Email address field exposed in API endpoint",
                PiiPatterns.EMAIL, "Contact Information",
                "Evaluate whether the email address is necessary in this response. " +
                        "Consider returning a masked version (e.g. u***@example.com)."));

        rules.add(FieldNameRule.of(
                "PHONE_EXPOSURE", Severity.MEDIUM,
                "Phone or mobile number field exposed in API endpoint",
                PiiPatterns.PHONE, "Contact Information",
                "Phone numbers are personal contact data. " +
                        "Return only what is strictly necessary and consider masking."));

        // ---- MEDIUM: Personal Information -----------------------------------

        rules.add(FieldNameRule.of(
                "DOB_EXPOSURE", Severity.MEDIUM,
                "Date of birth field exposed in API endpoint",
                PiiPatterns.DATE_OF_BIRTH, "Personal Information",
                "Date of birth is sensitive PII. " +
                        "Expose only if required; consider returning age range instead."));

        rules.add(FieldNameRule.of(
                "HEALTH_EXPOSURE", Severity.MEDIUM,
                "Health or medical data field exposed in API endpoint",
                PiiPatterns.HEALTH, "Health Data",
                "Medical data is regulated under HIPAA and similar laws. " +
                        "Ensure access is strictly controlled and data is minimised."));

        rules.add(FieldNameRule.of(
                "BIOMETRIC_EXPOSURE", Severity.MEDIUM,
                "Biometric data field exposed in API endpoint",
                PiiPatterns.BIOMETRIC, "Biometric Data",
                "Biometric data is highly sensitive. " +
                        "Remove from the API response or restrict access with strong authorisation."));

        rules.add(FieldNameRule.of(
                "GENDER_EXPOSURE", Severity.MEDIUM,
                "Gender field exposed in API endpoint",
                PiiPatterns.GENDER, "Personal Information",
                "Gender is sensitive personal data under GDPR and similar regulations. " +
                        "Expose only if strictly necessary for the use case."));

        rules.add(FieldNameRule.of(
                "SALARY_EXPOSURE", Severity.MEDIUM,
                "Salary or income field exposed in API endpoint",
                PiiPatterns.SALARY, "Financial",
                "Salary and income data is sensitive. " +
                        "Restrict access with appropriate authorisation and consider field-level encryption."));

        // ---- LOW: Location & Network ----------------------------------------

        rules.add(FieldNameRule.of(
                "ADDRESS_EXPOSURE", Severity.LOW,
                "Physical address field exposed in API endpoint",
                PiiPatterns.ADDRESS, "Location",
                "Physical addresses are personal data. " +
                        "Confirm this field is required and that access is appropriately restricted."));

        rules.add(FieldNameRule.of(
                "LOCATION_EXPOSURE", Severity.LOW,
                "Geographic coordinates or location data exposed in API endpoint",
                PiiPatterns.LOCATION, "Location",
                "Precise location data can be used to track individuals. " +
                        "Reduce precision or restrict access if not strictly necessary."));

        rules.add(FieldNameRule.of(
                "IP_ADDRESS_EXPOSURE", Severity.LOW,
                "IP address field exposed in API endpoint",
                PiiPatterns.IP_ADDRESS, "Network",
                "IP addresses are personal data under GDPR. " +
                        "Confirm this field is necessary and log appropriately."));

        rules.add(FieldNameRule.of(
                "ETHNICITY_EXPOSURE", Severity.LOW,
                "Ethnicity or race field exposed in API endpoint",
                PiiPatterns.ETHNICITY, "Personal Information",
                "Ethnicity and race are special-category data under GDPR. " +
                        "Ensure explicit consent and a lawful basis for processing."));

        // ---- INFO: Annotation-based -----------------------------------------

        rules.add(AnnotationRule.forAnnotation(
                "EMAIL_ANNOTATION", Severity.MEDIUM,
                "Field carries @Email annotation confirming it holds email address data",
                "Email", "Contact Information",
                "Evaluate whether the email address is necessary in this response. " +
                        "Consider returning a masked version."));

        rules.add(AnnotationRule.forJsonIgnore());

        return rules;
    }
}
