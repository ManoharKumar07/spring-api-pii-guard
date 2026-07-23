package io.github.manoharkumar07.piiguard.rules;

import io.github.manoharkumar07.piiguard.engine.Finding;
import io.github.manoharkumar07.piiguard.model.DtoInfo;
import io.github.manoharkumar07.piiguard.model.FieldInfo;
import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;
import io.github.manoharkumar07.piiguard.rules.patterns.PiiPatterns;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class FieldNameRuleTest {

    private ScannedEndpoint dummyEndpoint;

    @BeforeEach
    void setUp() {
        dummyEndpoint = new ScannedEndpoint(
                "GET", "/api/test", "com.example.TestController", "getTest",
                null, null, List.of(), List.of()
        );
    }

    // -----------------------------------------------------------------------
    // Normalisation tests
    // -----------------------------------------------------------------------

    @Test
    void normalisesLowercase() {
        assertThat(FieldNameRule.normalise("password")).isEqualTo("password");
    }

    @Test
    void normalisesCamelCase() {
        assertThat(FieldNameRule.normalise("socialSecurityNumber")).isEqualTo("social_security_number");
    }

    @Test
    void normalisesPasswordHash() {
        assertThat(FieldNameRule.normalise("passwordHash")).isEqualTo("password_hash");
    }

    @Test
    void normalisesHyphens() {
        assertThat(FieldNameRule.normalise("api-key")).isEqualTo("api_key");
    }

    @Test
    void normalisesAllUppercase() {
        // All-uppercase "SSN" has no lowercase-before-uppercase transitions,
        // so it is simply lowercased without underscores inserted.
        assertThat(FieldNameRule.normalise("SSN")).isEqualTo("ssn");
    }

    // -----------------------------------------------------------------------
    // Password pattern tests
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"password", "passwd", "pwd", "passwordHash", "confirmPassword",
            "user_password", "passphrase", "newPasswd"})
    void detectsPasswordVariants(String fieldName) {
        FieldNameRule rule = passwordRule();
        Optional<Finding> finding = rule.evaluate(field(fieldName), dummyEndpoint,
                "com.example.Dto", true);

        assertThat(finding).isPresent();
        assertThat(finding.get().severity()).isEqualTo(Severity.CRITICAL);
        assertThat(finding.get().ruleId()).isEqualTo("PASSWORD_EXPOSURE");
    }

    @ParameterizedTest
    @ValueSource(strings = {"username", "displayName", "title", "description", "productName",
            "category", "createdAt", "updatedAt", "status", "type"})
    void doesNotFlagSafeFieldNames(String fieldName) {
        FieldNameRule rule = passwordRule();
        Optional<Finding> finding = rule.evaluate(field(fieldName), dummyEndpoint,
                "com.example.Dto", true);

        assertThat(finding).isEmpty();
    }

    // -----------------------------------------------------------------------
    // SSN pattern tests
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"ssn", "socialSecurityNumber", "social_security_number",
            "userSsn", "ssnNumber", "SSN"})
    void detectsSsnVariants(String fieldName) {
        FieldNameRule rule = ssnRule();
        Optional<Finding> finding = rule.evaluate(field(fieldName), dummyEndpoint,
                "com.example.Dto", true);

        assertThat(finding).isPresent();
        assertThat(finding.get().severity()).isEqualTo(Severity.HIGH);
    }

    // -----------------------------------------------------------------------
    // Email pattern tests
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"email", "emailAddress", "userEmail", "primaryEmail", "e_mail"})
    void detectsEmailVariants(String fieldName) {
        FieldNameRule rule = emailRule();
        Optional<Finding> finding = rule.evaluate(field(fieldName), dummyEndpoint,
                "com.example.Dto", true);

        assertThat(finding).isPresent();
        assertThat(finding.get().severity()).isEqualTo(Severity.MEDIUM);
    }

    // -----------------------------------------------------------------------
    // Finding content tests
    // -----------------------------------------------------------------------

    @Test
    void findingContainsFieldName() {
        FieldNameRule rule = passwordRule();
        FieldInfo f = field("password");
        Finding finding = rule.evaluate(f, dummyEndpoint, "com.example.UserDto", true).orElseThrow();

        assertThat(finding.fieldName()).isEqualTo("password");
        assertThat(finding.fieldJsonName()).isEqualTo("password");
    }

    @Test
    void findingContainsEndpointContext() {
        FieldNameRule rule = passwordRule();
        Finding finding = rule.evaluate(field("password"), dummyEndpoint, "com.example.UserDto", true)
                .orElseThrow();

        assertThat(finding.endpointPath()).isEqualTo("/api/test");
        assertThat(finding.httpMethod()).isEqualTo("GET");
        assertThat(finding.controllerClass()).isEqualTo("com.example.TestController");
    }

    @Test
    void findingReflectsResponseBodyContext() {
        FieldNameRule rule = passwordRule();
        Finding responseBodyFinding = rule.evaluate(field("password"), dummyEndpoint,
                "com.example.Dto", true).orElseThrow();

        assertThat(responseBodyFinding.isInResponseBody()).isTrue();
        assertThat(responseBodyFinding.isInRequestBody()).isFalse();
    }

    @Test
    void findingReflectsRequestBodyContext() {
        FieldNameRule rule = passwordRule();
        Finding requestBodyFinding = rule.evaluate(field("password"), dummyEndpoint,
                "com.example.Dto", false).orElseThrow();

        assertThat(requestBodyFinding.isInResponseBody()).isFalse();
        assertThat(requestBodyFinding.isInRequestBody()).isTrue();
    }

    @Test
    void findingContainsDtoClassName() {
        FieldNameRule rule = passwordRule();
        Finding finding = rule.evaluate(field("password"), dummyEndpoint,
                "com.example.UserResponseDto", true).orElseThrow();

        assertThat(finding.dtoClassName()).isEqualTo("com.example.UserResponseDto");
    }

    @Test
    void findingContainsNonEmptyRecommendation() {
        FieldNameRule rule = passwordRule();
        Finding finding = rule.evaluate(field("password"), dummyEndpoint,
                "com.example.Dto", true).orElseThrow();

        assertThat(finding.recommendation()).isNotBlank();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static FieldNameRule passwordRule() {
        return FieldNameRule.of("PASSWORD_EXPOSURE", Severity.CRITICAL,
                "Password exposed", PiiPatterns.PASSWORD, "Credentials",
                "Remove this field from the response DTO.");
    }

    private static FieldNameRule ssnRule() {
        return FieldNameRule.of("SSN_EXPOSURE", Severity.HIGH,
                "SSN exposed", PiiPatterns.SSN, "Government ID",
                "Mask or remove this field.");
    }

    private static FieldNameRule emailRule() {
        return FieldNameRule.of("EMAIL_EXPOSURE", Severity.MEDIUM,
                "Email exposed", PiiPatterns.EMAIL, "Contact Information",
                "Consider masking this field.");
    }

    private static FieldInfo field(String name) {
        return new FieldInfo(name, name, "String", false, null, List.of(), List.of());
    }

    private static FieldInfo fieldWithJsonName(String name, String jsonName) {
        return new FieldInfo(name, jsonName, "String", false, null, List.of(), List.of());
    }

    @Test
    void usesJsonNameForPatternMatching() {
        // The @JsonProperty name is what's serialised — it should be matched, not the Java name
        FieldNameRule rule = passwordRule();
        // Java name: "secret", JSON name: "password"
        FieldInfo f = fieldWithJsonName("secret", "password");
        assertThat(rule.evaluate(f, dummyEndpoint, "com.example.Dto", true)).isPresent();
    }

    @Test
    void noMatchWhenJsonNameIsSafe() {
        FieldNameRule rule = passwordRule();
        // Java field name contains "password" but @JsonProperty overrides the serialised name.
        // The rule must match on jsonName ("displayValue") not on the Java name ("userPassword").
        FieldInfo f = fieldWithJsonName("userPassword", "displayValue");
        // "displayValue" normalises to "display_value" — does NOT contain "password" → no finding
        assertThat(rule.evaluate(f, dummyEndpoint, "com.example.Dto", true)).isEmpty();
    }
}
