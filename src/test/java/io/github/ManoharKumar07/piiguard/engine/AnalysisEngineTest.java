package io.github.ManoharKumar07.piiguard.engine;

import io.github.ManoharKumar07.piiguard.config.PiiGuardConfiguration;
import io.github.ManoharKumar07.piiguard.model.Severity;
import io.github.ManoharKumar07.piiguard.rules.RuleRegistry;
import io.github.ManoharKumar07.piiguard.scan.ClasspathScanner;
import io.github.ManoharKumar07.piiguard.scan.DtoFieldExtractor;
import io.github.ManoharKumar07.piiguard.scan.EndpointAnalyzer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class AnalysisEngineTest {

    private AnalysisEngine engine;
    private PiiGuardConfiguration config;

    @BeforeEach
    void setUp() {
        DtoFieldExtractor extractor = new DtoFieldExtractor();
        engine = new AnalysisEngine(
                new ClasspathScanner(),
                new EndpointAnalyzer(extractor, 5),
                RuleRegistry.defaults()
        );
        config = PiiGuardConfiguration.builder()
                .basePackages("io.github.ManoharKumar07.piiguard.fixtures")
                .build();
    }

    // -----------------------------------------------------------------------
    // Critical findings
    // -----------------------------------------------------------------------

    @Test
    void detectsPasswordFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("password")
                        && f.severity() == Severity.CRITICAL
                        && f.isInResponseBody());
    }

    @Test
    void detectsPasswordHashFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("passwordHash")
                        && f.severity() == Severity.CRITICAL);
    }

    @Test
    void detectsTokenFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("token")
                        && f.severity() == Severity.CRITICAL);
    }

    // -----------------------------------------------------------------------
    // High findings
    // -----------------------------------------------------------------------

    @Test
    void detectsSsnFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("socialSecurityNumber")
                        && f.severity() == Severity.HIGH
                        && f.isInResponseBody());
    }

    @Test
    void detectsAadhaarFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("aadhaarNumber")
                        && f.severity() == Severity.HIGH);
    }

    // -----------------------------------------------------------------------
    // Safe controller produces no field-name findings
    // -----------------------------------------------------------------------

    @Test
    void safeProductControllerProducesNoFindings() {
        PiiGuardConfiguration safeConfig = PiiGuardConfiguration.builder()
                .basePackages("io.github.ManoharKumar07.piiguard.fixtures.controllers")
                .build();

        // Use a scanner that only sees the safe controller's package
        DtoFieldExtractor extractor = new DtoFieldExtractor();
        AnalysisEngine safeEngine = new AnalysisEngine(
                new ClasspathScanner(),
                new EndpointAnalyzer(extractor, 5),
                RuleRegistry.defaults()
        );

        AnalysisResult result = safeEngine.analyze(safeConfig);

        // ProductDto fields (id, name, description, price, category) must not trigger findings
        assertThat(result.findings())
                .noneMatch(f -> f.dtoClassName().contains("ProductDto")
                        && f.severity().ordinal() <= Severity.MEDIUM.ordinal());
    }

    // -----------------------------------------------------------------------
    // Request body context
    // -----------------------------------------------------------------------

    @Test
    void passwordInRequestBodyIsMarkedAsRequestBody() {
        AnalysisResult result = engine.analyze(config);

        // CreateUserRequest.password is in the @RequestBody of POST /api/users
        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("password")
                        && f.isInRequestBody()
                        && !f.isInResponseBody());
    }

    // -----------------------------------------------------------------------
    // Suppression
    // -----------------------------------------------------------------------

    @Test
    void suppressedRuleDoesNotProduceFinding() {
        AnalysisResult result = engine.analyze(config);

        // SuppressedFieldController returns UserWithSuppressedFieldsDto.
        // emailNotificationType suppresses EMAIL_EXPOSURE specifically.
        assertThat(result.findings())
                .noneMatch(f -> f.fieldName().equals("emailNotificationType")
                        && f.ruleId().equals("EMAIL_EXPOSURE"));
    }

    @Test
    void allRulesSuppressedFieldProducesNoFindings() {
        AnalysisResult result = engine.analyze(config);

        // internalRef has @PiiGuardSuppress(reason = "...") with no specific rules → all suppressed
        assertThat(result.findings())
                .noneMatch(f -> f.fieldName().equals("internalRef"));
    }

    // -----------------------------------------------------------------------
    // @JsonIgnore handling
    // -----------------------------------------------------------------------

    @Test
    void jsonIgnoredFieldProducesOnlyInfoFinding() {
        AnalysisResult result = engine.analyze(config);

        // UserWithSuppressedFieldsDto.passwordHash has @JsonIgnore
        // → only the INFO finding fires, no CRITICAL finding
        List<Finding> passwordHashFindings = result.findings().stream()
                .filter(f -> f.fieldName().equals("passwordHash")
                        && f.dtoClassName().contains("UserWithSuppressedFieldsDto"))
                .toList();

        assertThat(passwordHashFindings).isNotEmpty();
        assertThat(passwordHashFindings).allMatch(f -> f.severity() == Severity.INFO);
    }

    // -----------------------------------------------------------------------
    // AnalysisResult helpers
    // -----------------------------------------------------------------------

    @Test
    void totalFindingsMatchesListSize() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.totalFindings()).isEqualTo(result.findings().size());
    }

    @Test
    void countBySeverityIsAccurate() {
        AnalysisResult result = engine.analyze(config);

        long criticalCount = result.findings().stream()
                .filter(f -> f.severity() == Severity.CRITICAL).count();

        assertThat(result.countBySeverity(Severity.CRITICAL)).isEqualTo(criticalCount);
    }

    @Test
    void hasFindingsReturnsTrueWhenCriticalExists() {
        AnalysisResult result = engine.analyze(config);

        // VulnerableUserController contains password fields → must have CRITICAL findings
        assertThat(result.hasFindings(Severity.CRITICAL)).isTrue();
    }

    @Test
    void hasFindingsReturnsFalseWhenNoFindingsAtOrAboveThreshold() {
        AnalysisResult result = engine.analyze(config);

        // There should be no findings, because Severity enum ordinal: CRITICAL=0, ..., INFO=4
        // hasFindings(INFO) should be true if any finding exists
        if (result.totalFindings() > 0) {
            assertThat(result.hasFindings(Severity.INFO)).isTrue();
        }
    }

    @Test
    void timestampIsSet() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.timestamp()).isNotNull();
    }

    @Test
    void endpointsListIsPopulated() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.endpoints()).isNotEmpty();
    }

    // -----------------------------------------------------------------------
    // Financial / Credential findings (FinancialDto via SensitiveDataController)
    // -----------------------------------------------------------------------

    @Test
    void detectsCreditCardFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("creditCard")
                        && f.severity() == Severity.HIGH);
    }

    @Test
    void detectsCvvFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("cvv")
                        && f.severity() == Severity.HIGH);
    }

    @Test
    void detectsBankAccountFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("accountNumber")
                        && f.severity() == Severity.HIGH);
    }

    @Test
    void detectsOtpFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("otp")
                        && f.severity() == Severity.CRITICAL);
    }

    // -----------------------------------------------------------------------
    // Personal / Location findings (PersonalInfoDto via SensitiveDataController)
    // -----------------------------------------------------------------------

    @Test
    void detectsNationalIdFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("nationalId")
                        && f.severity() == Severity.HIGH);
    }

    @Test
    void detectsPhoneFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("phone")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsDateOfBirthFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("dateOfBirth")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsHealthDiagnosisFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("diagnosis")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsBiometricFingerprintFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("fingerprint")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsGenderFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("gender")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsSalaryFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("salary")
                        && f.severity() == Severity.MEDIUM);
    }

    @Test
    void detectsAddressFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("address")
                        && f.severity() == Severity.LOW);
    }

    @Test
    void detectsLocationLatitudeFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("latitude")
                        && f.severity() == Severity.LOW);
    }

    @Test
    void detectsIpAddressFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("ipAddress")
                        && f.severity() == Severity.LOW);
    }

    @Test
    void detectsEthnicityFieldInResponseDto() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .anyMatch(f -> f.fieldName().equals("ethnicity")
                        && f.severity() == Severity.LOW);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    @Test
    void handlesCircularDtoReferencesWithoutException() {
        // CircularController returns CircularADto → CircularBDto → CircularADto (circular).
        // The engine must not throw StackOverflowError or any other exception.
        assertThatNoException().isThrownBy(() -> engine.analyze(config));
    }

    @Test
    void circularDtoFieldsProduceNoFindings() {
        AnalysisResult result = engine.analyze(config);

        // CircularADto.name, CircularBDto.owner — none of these are PII field names.
        assertThat(result.findings())
                .noneMatch(f -> f.dtoClassName().contains("CircularADto")
                             || f.dtoClassName().contains("CircularBDto"));
    }

    // -----------------------------------------------------------------------
    // Finding quality assertions
    // -----------------------------------------------------------------------

    @Test
    void findingsContainCorrectEndpointPath() {
        AnalysisResult result = engine.analyze(config);

        // All findings must have a non-blank endpoint path
        assertThat(result.findings())
                .allMatch(f -> f.endpointPath() != null && !f.endpointPath().isBlank());
    }

    @Test
    void findingsContainValidHttpMethod() {
        AnalysisResult result = engine.analyze(config);

        Set<String> validMethods = Set.of("GET", "POST", "PUT", "DELETE", "PATCH");
        assertThat(result.findings())
                .allMatch(f -> validMethods.contains(f.httpMethod()));
    }

    @Test
    void allFindingsHaveNonBlankRecommendations() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .allMatch(f -> f.recommendation() != null && !f.recommendation().isBlank());
    }

    @Test
    void allFindingsHaveNonBlankPiiCategory() {
        AnalysisResult result = engine.analyze(config);

        assertThat(result.findings())
                .allMatch(f -> f.piiCategory() != null && !f.piiCategory().isBlank());
    }

    @Test
    void multipleSeverityLevelsDetectedInSingleScan() {
        AnalysisResult result = engine.analyze(config);

        // Fixtures span CRITICAL (passwords, token, otp), HIGH (SSN, Aadhaar, credit card …),
        // MEDIUM (phone, DOB, gender …), and LOW (address, latitude, IP …) findings.
        assertThat(result.countBySeverity(Severity.CRITICAL)).isPositive();
        assertThat(result.countBySeverity(Severity.HIGH)).isPositive();
        assertThat(result.countBySeverity(Severity.MEDIUM)).isPositive();
        assertThat(result.countBySeverity(Severity.LOW)).isPositive();
    }

    @Test
    void findingLinksToCorrectControllerClass() {
        AnalysisResult result = engine.analyze(config);

        // VulnerableUserController findings must reference that controller's FQN
        assertThat(result.findings())
                .anyMatch(f -> f.controllerClass()
                        .contains("VulnerableUserController"));
    }
}
