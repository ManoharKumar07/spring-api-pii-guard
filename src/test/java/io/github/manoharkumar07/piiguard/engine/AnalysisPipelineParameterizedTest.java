package io.github.manoharkumar07.piiguard.engine;

import io.github.manoharkumar07.piiguard.model.FieldInfo;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;
import io.github.manoharkumar07.piiguard.rules.RuleRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parameterized tests that verify every PII pattern in {@link RuleRegistry#defaults()}
 * against realistic field-name variants and a set of deliberately safe names.
 *
 * <p>Each test group drives a single {@code @ParameterizedTest} method with multiple
 * field-name variants through all rules from the default registry. A rule match is
 * detected using the direct {@link io.github.manoharkumar07.piiguard.rules.PiiDetectionRule#evaluate}
 * API — this is faster than a full classpath scan and lets us assert both the presence
 * AND the expected severity of the match.
 *
 * <p>The synthetic {@link FieldInfo} and {@link ScannedEndpoint} objects used here carry
 * empty annotation/suppression lists, so only field-name rules ({@link io.github.manoharkumar07.piiguard.rules.FieldNameRule})
 * can fire; annotation-based rules require actual annotation metadata.
 */
class AnalysisPipelineParameterizedTest {

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Creates a synthetic FieldInfo with the given name (used as both Java and JSON name). */
    private static FieldInfo syntheticField(String name) {
        return new FieldInfo(name, name, "String", false, null, List.of(), List.of());
    }

    /** A minimal ScannedEndpoint — sufficient for FieldNameRule evaluation. */
    private static ScannedEndpoint syntheticEndpoint() {
        return new ScannedEndpoint(
                "GET", "/api/synthetic", "SyntheticController", "getData",
                null, null, List.of(), List.of());
    }

    /**
     * Returns {@code true} when any rule in the default registry with the given
     * severity produces a finding for {@code fieldName}.
     */
    private boolean anyRuleMatchesWithSeverity(String fieldName, Severity expected) {
        FieldInfo field = syntheticField(fieldName);
        ScannedEndpoint ep = syntheticEndpoint();
        return RuleRegistry.defaults().rules().stream()
                .filter(r -> r.severity() == expected)
                .anyMatch(rule -> rule.evaluate(field, ep, "SyntheticDto", true).isPresent());
    }

    /** Returns {@code true} when ANY rule in the default registry produces a finding. */
    private boolean anyRuleMatches(String fieldName) {
        FieldInfo field = syntheticField(fieldName);
        ScannedEndpoint ep = syntheticEndpoint();
        return RuleRegistry.defaults().rules().stream()
                .anyMatch(rule -> rule.evaluate(field, ep, "SyntheticDto", true).isPresent());
    }

    // -----------------------------------------------------------------------
    // CRITICAL — Credentials & Secrets
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "password variant: {0}")
    @ValueSource(strings = {"password", "passwd", "pwd", "passwordHash",
            "confirmPassword", "userPassword", "passphrase", "newPasswd"})
    void detectsPasswordVariantsAsCritical(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.CRITICAL)).isTrue();
    }

    @ParameterizedTest(name = "secret/token variant: {0}")
    @ValueSource(strings = {"secret", "apiKey", "api_key", "token",
            "accessToken", "privateKey"})
    void detectsSecretKeyVariantsAsCritical(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.CRITICAL)).isTrue();
    }

    @ParameterizedTest(name = "OTP variant: {0}")
    @ValueSource(strings = {"otp", "otpCode", "mfaCode", "verificationCode"})
    void detectsOtpVariantsAsCritical(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.CRITICAL)).isTrue();
    }

    // -----------------------------------------------------------------------
    // HIGH — Government IDs
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "SSN variant: {0}")
    @ValueSource(strings = {"ssn", "socialSecurityNumber",
            "social_security_number", "ssnNumber"})
    void detectsSsnVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    @ParameterizedTest(name = "Aadhaar variant: {0}")
    @ValueSource(strings = {"aadhaar", "aadhaarNumber", "aadhar"})
    void detectsAadhaarVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    @ParameterizedTest(name = "national ID variant: {0}")
    @ValueSource(strings = {"nationalId", "passportNumber", "drivingLicense"})
    void detectsNationalIdVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    // -----------------------------------------------------------------------
    // HIGH — Financial
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "credit card variant: {0}")
    @ValueSource(strings = {"creditCard", "cardNumber", "debitCard"})
    void detectsCreditCardVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    @ParameterizedTest(name = "CVV variant: {0}")
    @ValueSource(strings = {"cvv", "cvc", "cardVerification"})
    void detectsCvvVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    @ParameterizedTest(name = "bank account variant: {0}")
    @ValueSource(strings = {"accountNumber", "bankAccount", "routingNumber"})
    void detectsBankAccountVariantsAsHigh(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.HIGH)).isTrue();
    }

    // -----------------------------------------------------------------------
    // MEDIUM — Contact Information
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "email variant: {0}")
    @ValueSource(strings = {"email", "emailAddress", "userEmail", "e_mail"})
    void detectsEmailVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    @ParameterizedTest(name = "phone variant: {0}")
    @ValueSource(strings = {"phone", "mobile", "phoneNumber", "telephone"})
    void detectsPhoneVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    // -----------------------------------------------------------------------
    // MEDIUM — Personal Information
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "date-of-birth variant: {0}")
    @ValueSource(strings = {"dateOfBirth", "dob", "birthDate"})
    void detectsDobVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    @ParameterizedTest(name = "health data variant: {0}")
    @ValueSource(strings = {"diagnosis", "medicalRecord", "prescription"})
    void detectsHealthVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    @ParameterizedTest(name = "biometric variant: {0}")
    @ValueSource(strings = {"fingerprint", "biometric", "faceId"})
    void detectsBiometricVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    @ParameterizedTest(name = "gender variant: {0}")
    @ValueSource(strings = {"gender", "genderIdentity", "userGender"})
    void detectsGenderVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    @ParameterizedTest(name = "salary/income variant: {0}")
    @ValueSource(strings = {"salary", "income", "wage", "compensation"})
    void detectsSalaryVariantsAsMedium(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.MEDIUM)).isTrue();
    }

    // -----------------------------------------------------------------------
    // LOW — Location & Network
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "address variant: {0}")
    @ValueSource(strings = {"address", "streetAddress", "zipCode"})
    void detectsAddressVariantsAsLow(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.LOW)).isTrue();
    }

    @ParameterizedTest(name = "location variant: {0}")
    @ValueSource(strings = {"latitude", "longitude", "coordinates"})
    void detectsLocationVariantsAsLow(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.LOW)).isTrue();
    }

    @ParameterizedTest(name = "IP address variant: {0}")
    @ValueSource(strings = {"ipAddress", "clientIp", "remoteAddr"})
    void detectsIpAddressVariantsAsLow(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.LOW)).isTrue();
    }

    @ParameterizedTest(name = "ethnicity variant: {0}")
    @ValueSource(strings = {"ethnicity", "race", "nationality"})
    void detectsEthnicityVariantsAsLow(String fieldName) {
        assertThat(anyRuleMatchesWithSeverity(fieldName, Severity.LOW)).isTrue();
    }

    // -----------------------------------------------------------------------
    // Negative cases — safe field names that must NOT trigger any finding
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "safe name: {0}")
    @ValueSource(strings = {
            "username", "displayName", "title", "description", "productName",
            "createdAt", "id", "status", "type", "category"})
    void doesNotFlagSafeFieldNames(String fieldName) {
        assertThat(anyRuleMatches(fieldName)).isFalse();
    }

    // -----------------------------------------------------------------------
    // Cross-category: finding carries correct severity for each matched rule
    // -----------------------------------------------------------------------

    @Test
    void passwordRuleProducesCriticalFinding() {
        FieldInfo f = syntheticField("password");
        ScannedEndpoint ep = syntheticEndpoint();
        boolean criticalFound = RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("PASSWORD_EXPOSURE"))
                .anyMatch(rule -> rule.evaluate(f, ep, "TestDto", true)
                        .map(finding -> finding.severity() == Severity.CRITICAL)
                        .orElse(false));
        assertThat(criticalFound).isTrue();
    }

    @Test
    void ssnRuleProducesHighFinding() {
        FieldInfo f = syntheticField("ssn");
        ScannedEndpoint ep = syntheticEndpoint();
        boolean highFound = RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("SSN_EXPOSURE"))
                .anyMatch(rule -> rule.evaluate(f, ep, "TestDto", true)
                        .map(finding -> finding.severity() == Severity.HIGH)
                        .orElse(false));
        assertThat(highFound).isTrue();
    }

    @Test
    void emailRuleProducesMediumFinding() {
        FieldInfo f = syntheticField("email");
        ScannedEndpoint ep = syntheticEndpoint();
        boolean mediumFound = RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("EMAIL_EXPOSURE"))
                .anyMatch(rule -> rule.evaluate(f, ep, "TestDto", true)
                        .map(finding -> finding.severity() == Severity.MEDIUM)
                        .orElse(false));
        assertThat(mediumFound).isTrue();
    }

    @Test
    void findingContainsRecommendation() {
        FieldInfo f = syntheticField("password");
        ScannedEndpoint ep = syntheticEndpoint();
        RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("PASSWORD_EXPOSURE"))
                .findFirst()
                .flatMap(rule -> rule.evaluate(f, ep, "TestDto", true))
                .ifPresent(finding -> assertThat(finding.recommendation()).isNotBlank());
    }

    @Test
    void findingReflectsIsInResponseBody() {
        FieldInfo f = syntheticField("password");
        ScannedEndpoint ep = syntheticEndpoint();
        RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("PASSWORD_EXPOSURE"))
                .findFirst()
                .flatMap(rule -> rule.evaluate(f, ep, "TestDto", true))
                .ifPresent(finding -> {
                    assertThat(finding.isInResponseBody()).isTrue();
                    assertThat(finding.isInRequestBody()).isFalse();
                });
    }

    @Test
    void findingReflectsIsInRequestBody() {
        FieldInfo f = syntheticField("password");
        ScannedEndpoint ep = syntheticEndpoint();
        RuleRegistry.defaults().rules().stream()
                .filter(r -> r.ruleId().equals("PASSWORD_EXPOSURE"))
                .findFirst()
                .flatMap(rule -> rule.evaluate(f, ep, "TestDto", false))
                .ifPresent(finding -> {
                    assertThat(finding.isInRequestBody()).isTrue();
                    assertThat(finding.isInResponseBody()).isFalse();
                });
    }
}
