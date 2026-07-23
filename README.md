# Spring API PII Guard

A JUnit 5 extension that automatically detects PII (Personally Identifiable Information) and sensitive data exposure in Spring Boot REST APIs — at test time, with zero application code changes.

[![Java 17+](https://img.shields.io/badge/Java-17%2B-blue)](https://adoptium.net/)
[![Spring Boot 3.x](https://img.shields.io/badge/Spring%20Boot-3.x-green)](https://spring.io/projects/spring-boot)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

PII Guard scans your Spring Boot controllers and their response/request DTOs during `mvn test`, applies 20+ detection rules across categories such as credentials, government IDs, financial data, and personal information, and produces:

- **An interactive HTML report** sorted by severity with filter, search, and copy-to-clipboard controls.
- **Structured findings** listing the exact field, DTO class, endpoint path, HTTP method, and an actionable fix recommendation for each issue.
- **Optional test failure** — configure `failOnFindings(true)` to fail the build when sensitive data is detected.

---

## Quick Start

### 1. Add the dependency

```xml
<dependency>
    <groupId>io.github.manoharkumar07</groupId>
    <artifactId>spring-api-pii-guard</artifactId>
    <version>1.0.0</version>
    <scope>test</scope>
</dependency>
```

### 2. Add the annotation to any test class

```java
@ExtendWith(PiiGuardExtension.class)
class PiiGuardScanTest {

    @Test
    void scanCompletes() {
        // The scan runs automatically before this test.
        // Results are logged and an HTML report is written to target/pii-guard/.
    }
}
```

### 3. Run the tests

```bash
mvn test
```

The report is written to `target/pii-guard/pii-guard-report.html`. Open it in any browser.

> **Auto-detection:** If your project has a class annotated with `@SpringBootApplication`, PII Guard automatically detects its package and scans from there. No configuration required.

---

## Configuration

Use `@RegisterExtension` with a custom `PiiGuardConfiguration` for advanced control:

```java
class PiiGuardScanTest {

    @RegisterExtension
    static PiiGuardExtension piiGuard = new PiiGuardExtension(
        PiiGuardConfiguration.builder()
            .basePackages("com.example.api")       // packages to scan
            .failOnFindings(true)                   // fail the build if issues found
            .minimumSeverity(Severity.HIGH)         // only fail for HIGH and above
            .reportOutputDirectory(Path.of("target/pii-guard"))
            .maxDtoDepth(5)                         // max DTO nesting depth
            .build()
    );

    @Test
    void noCriticalFindings() {
        assertThat(piiGuard.getLatestResult()
            .countBySeverity(Severity.CRITICAL)).isZero();
    }
}
```

### Configuration reference

| Option | Default | Description |
|---|---|---|
| `basePackages` | *(auto-detect)* | Packages to scan for `@RestController` classes. Detected from `@SpringBootApplication` when empty. |
| `failOnFindings` | `false` | When `true`, throws `PiiGuardAssertionError` if any finding meets the minimum severity. |
| `minimumSeverity` | `HIGH` | Findings below this severity are ignored when `failOnFindings` is `true`. |
| `reportOutputDirectory` | `target/pii-guard` | Directory where `pii-guard-report.html` is written. Created automatically. |
| `maxDtoDepth` | `5` | Maximum recursion depth for nested DTO analysis. Prevents infinite loops on circular references. |

---

## Suppression — Handling False Positives

When a finding is a known false positive, annotate the field with `@PiiGuardSuppress`:

```java
// Suppress a specific rule
@PiiGuardSuppress(rules = "EMAIL_EXPOSURE", reason = "Notification preference enum, not a personal email")
private String emailNotificationType;

// Suppress all rules for a field
@PiiGuardSuppress(reason = "Legacy identifier — safe to expose, verified by security review 2024-01-15")
private String legacyToken;
```

The `reason` attribute is **required** — it forces developers to document why the finding is not a real risk.

---

## Supported PII Categories

| Category | Severity | Example Fields Detected |
|---|---|---|
| Credentials | CRITICAL | `password`, `passwd`, `secret`, `apiKey`, `accessToken`, `otp` |
| Government ID | HIGH | `ssn`, `socialSecurityNumber`, `aadhaarNumber`, `nationalId`, `passportNumber` |
| Financial | HIGH | `creditCard`, `cardNumber`, `cvv`, `accountNumber`, `routingNumber` |
| Contact Information | MEDIUM | `email`, `phone`, `mobile`, `telephone` |
| Personal Information | MEDIUM | `dateOfBirth`, `dob`, `gender`, `diagnosis`, `salary`, `fingerprint` |
| Location | LOW | `address`, `street`, `latitude`, `longitude`, `ipAddress` |
| Serialisation Control | INFO | Fields annotated with `@JsonIgnore` (correctly hidden) |

> Field names are normalised before matching: `socialSecurityNumber`, `social_security_number`, and `social-security-number` all trigger the same rule.

---

## Accessing Results in Test Methods

When using `@RegisterExtension`, access findings programmatically:

```java
@RegisterExtension
static PiiGuardExtension piiGuard = new PiiGuardExtension(
    PiiGuardConfiguration.builder()
        .basePackages("com.example.api")
        .build()
);

@Test
void noCriticalFindings() {
    AnalysisResult result = piiGuard.getLatestResult();
    assertThat(result.countBySeverity(Severity.CRITICAL)).isZero();
}

@Test
void highFindingsAreDocumented() {
    AnalysisResult result = piiGuard.getLatestResult();
    // Custom assertions on result.findings() ...
}
```

---

## Custom Rules

Implement `PiiDetectionRule` to add project-specific detection logic:

```java
public class InternalTokenRule implements PiiDetectionRule {

    @Override
    public String ruleId() { return "INTERNAL_TOKEN_EXPOSURE"; }

    @Override
    public String description() { return "Internal session token exposed in response"; }

    @Override
    public Severity severity() { return Severity.CRITICAL; }

    @Override
    public Optional<Finding> evaluate(FieldInfo field, ScannedEndpoint endpoint,
                                      String dtoClassName, boolean isInResponseBody) {
        if (isInResponseBody && field.name().startsWith("internalSession")) {
            return Optional.of(new Finding(
                ruleId(), severity(), "Credentials",
                field.name(), field.jsonName(), dtoClassName,
                endpoint.path(), endpoint.httpMethod(), endpoint.controllerClass(),
                description(), "Remove or annotate with @JsonIgnore", false, true
            ));
        }
        return Optional.empty();
    }
}
```

Register with:

```java
RuleRegistry registry = RuleRegistry.defaults()
    .withAdditionalRules(List.of(new InternalTokenRule()));
```

---

## Compatibility Matrix

| Spring API PII Guard | Java | Spring Boot | JUnit 5 |
|---|---|---|---|
| 1.0.0 | 17+ | 3.x | 5.9+ |

Spring Boot 2.x is not supported. The library uses Spring Web annotations only (`provided` scope) — it does not start an application context.

---

## How It Works

The library uses **Java Reflection + ClassGraph** to analyse the compiled classpath during `mvn test`:

```
ClassGraph scans classpath
    → finds @RestController classes
        → Reflection inspects each method
            → extracts path, HTTP method, return type, @RequestBody type
                → walks DTO fields recursively (depth-limited, cycle-safe)
                    → applies 20+ PII detection rules per field
                        → produces Finding objects → HTML report
```

No application context is started. No Spring Boot test slice is used. The scan is deterministic and reproducible.

---

## Report Features

The generated HTML report (`target/pii-guard/pii-guard-report.html`) contains:

- **Executive Summary** — severity-breakdown stat cards (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Findings table** — filter by severity, search by field name or endpoint, copy-to-clipboard per row
- **Endpoint inventory** — all scanned endpoints with collapsible DTO field details
- **Recommendations** — actionable guidance grouped by PII category
- **Scan metadata** — timestamp, packages scanned, controller count, scan duration

The file is entirely self-contained (inline CSS and JS) — no web server required.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Add tests for any new rule or behaviour.
3. Run `mvn test` — all 278+ tests must pass.
4. Submit a pull request with a clear description of the change.

Please open an issue before implementing large changes to discuss the approach.

---

## License

This project is licensed under the [MIT License](LICENSE).
