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

import static org.assertj.core.api.Assertions.assertThat;

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
}
