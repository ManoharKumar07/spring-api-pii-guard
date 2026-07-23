# Changelog

All notable changes to Spring API PII Guard are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-07-23

### Added

#### Core Analysis Engine
- `AnalysisEngine` — orchestrates the full scan pipeline: classpath discovery → endpoint extraction → field analysis → findings
- `AnalysisResult` — immutable result record with `totalFindings()`, `countBySeverity()`, and `hasFindings()` helpers
- `Finding` — immutable record carrying rule ID, severity, PII category, field name, JSON name, DTO class, endpoint path, HTTP method, controller class, message, and recommendation

#### Classpath Scanner
- `ClasspathScanner` — discovers `@RestController` classes using ClassGraph across JARs, modules, and nested packages
- `EndpointAnalyzer` — extracts endpoint metadata (path, HTTP method, response/request DTOs, path variables, query parameters)
  - Full generic type resolution: `ResponseEntity<T>`, `List<T>`, `Map<K,V>`
  - Handles `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@RequestMapping`
- `DtoFieldExtractor` — recursively walks DTO fields using Reflection
  - Cycle detection via a `visited` set (prevents infinite recursion)
  - Depth limiting (configurable, default 5)
  - Inherited field support (walks superclass hierarchy)
  - `@JsonProperty` resolution for serialised field names

#### PII Detection Rule Engine
- `PiiDetectionRule` interface — stateless, thread-safe contract for custom rules
- `FieldNameRule` — matches normalised field names against compiled regex patterns
  - Normalisation: `camelCase` → `snake_case`, hyphens → underscores, lowercase
- `AnnotationRule` — detects PII based on field annotations (`@Email`, `@JsonIgnore`)
- `RuleRegistry` — ordered, immutable rule list with `defaults()`, `of()`, and `withAdditionalRules()` factories

#### 20+ Default Detection Rules

| Severity | Rule ID | Category | Examples |
|---|---|---|---|
| CRITICAL | `PASSWORD_EXPOSURE` | Credentials | `password`, `passwd`, `pwd` |
| CRITICAL | `SECRET_KEY_EXPOSURE` | Credentials | `secret`, `apiKey`, `accessToken` |
| CRITICAL | `OTP_EXPOSURE` | Credentials | `otp`, `mfaCode`, `verificationCode` |
| HIGH | `SSN_EXPOSURE` | Government ID | `ssn`, `socialSecurityNumber` |
| HIGH | `AADHAAR_EXPOSURE` | Government ID | `aadhaarNumber`, `aadharId` |
| HIGH | `NATIONAL_ID_EXPOSURE` | Government ID | `nationalId`, `passportNumber`, `panNumber` |
| HIGH | `CREDIT_CARD_EXPOSURE` | Financial | `creditCard`, `cardNumber` |
| HIGH | `CVV_EXPOSURE` | Financial | `cvv`, `cvc`, `cardVerification` |
| HIGH | `BANK_ACCOUNT_EXPOSURE` | Financial | `accountNumber`, `routingNumber`, `iban` |
| MEDIUM | `EMAIL_EXPOSURE` | Contact Information | `email`, `emailAddress` |
| MEDIUM | `PHONE_EXPOSURE` | Contact Information | `phone`, `mobile`, `telephone` |
| MEDIUM | `DOB_EXPOSURE` | Personal Information | `dateOfBirth`, `dob`, `birthDate` |
| MEDIUM | `HEALTH_EXPOSURE` | Health Data | `diagnosis`, `medicalRecord`, `patientId` |
| MEDIUM | `BIOMETRIC_EXPOSURE` | Biometric Data | `fingerprint`, `faceId`, `biometric` |
| MEDIUM | `GENDER_EXPOSURE` | Personal Information | `gender` |
| MEDIUM | `SALARY_EXPOSURE` | Financial | `salary`, `income`, `wage` |
| LOW | `ADDRESS_EXPOSURE` | Location | `address`, `streetAddress`, `zipCode` |
| LOW | `LOCATION_EXPOSURE` | Location | `latitude`, `longitude`, `gpsCoordinates` |
| LOW | `IP_ADDRESS_EXPOSURE` | Network | `ipAddress`, `clientIp`, `remoteAddr` |
| LOW | `ETHNICITY_EXPOSURE` | Personal Information | `ethnicity`, `race`, `nationality` |
| MEDIUM | `EMAIL_ANNOTATION` | Contact Information | fields carrying `@Email` |
| INFO | `JSON_IGNORE_CORRECT` | Serialisation Control | fields carrying `@JsonIgnore` |

#### JUnit 5 Extension
- `PiiGuardExtension` — implements `BeforeAllCallback`; runs the scan once per test class
  - `@ExtendWith(PiiGuardExtension.class)` — zero-config declarative registration
  - `@RegisterExtension static PiiGuardExtension` — programmatic registration with custom `PiiGuardConfiguration`
  - Auto-detection of base packages from `@SpringBootApplication`
  - Idempotent: skips re-running if already executed for the same test class in the same JVM session
  - `getLatestResult()` / `getLatestReportPath()` — instance accessors for `@RegisterExtension` usage
  - `getResult(ExtensionContext)` / `getReportPath(ExtensionContext)` — static accessors for test methods
- `PiiGuardConfiguration` — immutable configuration with a fluent builder
- `PiiGuardAssertionError` — thrown when `failOnFindings=true`; lists all findings in the message
- `@PiiGuardSuppress` — annotation to suppress specific rules (or all rules) on a field with a mandatory `reason`

#### HTML Report Generator
- `HtmlReportGenerator` — generates a single self-contained `.html` file with inline CSS and JavaScript
  - Six sections: Header, Executive Summary, Findings, Endpoint Inventory, Recommendations, Scan Metadata
  - Findings table: filter by severity, text search, copy-to-clipboard per row, sorted CRITICAL → INFO
  - Severity colour scheme: CRITICAL (red), HIGH (orange), MEDIUM (amber), LOW (blue), INFO (grey)
  - Zero external dependencies — no CDN, stylesheet, or script references
- `ReportGenerator` interface — strategy contract for alternate report formats

#### Test Coverage
- 278 tests covering all rule categories, edge cases (circular references, deeply nested DTOs, void endpoints), and the full analysis pipeline
- Parameterised tests for all 20+ PII patterns with positive and negative cases
- Integration test using `@ExtendWith(PiiGuardExtension.class)` with auto-detected base package

#### Documentation
- `README.md` — quick start, configuration reference, suppression guide, custom rules, compatibility matrix
- `CHANGELOG.md` — this file
- Full Javadoc on all public classes, methods, and annotations
- `LICENSE` — MIT

### Dependencies (runtime)

| Dependency | Version | Scope |
|---|---|---|
| `io.github.classgraph:classgraph` | 4.8.174 | compile (only runtime dependency) |

All other dependencies (`spring-web`, `junit-jupiter-api`, `slf4j-api`, `jackson-annotations`) are declared as `provided` and must be supplied by the consuming project.

---

[1.0.0]: https://github.com/ManoharKumar07/spring-api-pii-guard/releases/tag/v1.0.0
