package io.github.ManoharKumar07.piiguard.config;

import io.github.ManoharKumar07.piiguard.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable configuration object for a PII Guard scan.
 *
 * <p>Construct via {@link #builder()}:
 * <pre>{@code
 * PiiGuardConfiguration config = PiiGuardConfiguration.builder()
 *     .basePackages("com.example.api")
 *     .failOnFindings(true)
 *     .minimumSeverity(Severity.HIGH)
 *     .build();
 * }</pre>
 */
public final class PiiGuardConfiguration {

    private final List<String> basePackages;
    private final boolean failOnFindings;
    private final Severity minimumSeverity;
    private final Path reportOutputDirectory;
    private final int maxDtoDepth;

    private PiiGuardConfiguration(Builder builder) {
        this.basePackages = Collections.unmodifiableList(new ArrayList<>(builder.basePackages));
        this.failOnFindings = builder.failOnFindings;
        this.minimumSeverity = builder.minimumSeverity;
        this.reportOutputDirectory = builder.reportOutputDirectory;
        this.maxDtoDepth = builder.maxDtoDepth;
    }

    /** Packages to scan for {@code @RestController} classes. Empty list means auto-detect. */
    public List<String> basePackages() {
        return basePackages;
    }

    /** Whether to fail the test (throw {@code AssertionError}) when findings meet the minimum severity. */
    public boolean failOnFindings() {
        return failOnFindings;
    }

    /** Minimum severity that triggers a test failure when {@link #failOnFindings()} is {@code true}. */
    public Severity minimumSeverity() {
        return minimumSeverity;
    }

    /** Directory where the HTML report is written. Defaults to {@code target/pii-guard}. */
    public Path reportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Maximum depth for recursive DTO field analysis.
     * Prevents infinite recursion on circular DTO references. Defaults to 5.
     */
    public int maxDtoDepth() {
        return maxDtoDepth;
    }

    /** Creates a new {@link Builder} with default settings. */
    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link PiiGuardConfiguration}. */
    public static final class Builder {

        private List<String> basePackages = new ArrayList<>();
        private boolean failOnFindings = false;
        private Severity minimumSeverity = Severity.HIGH;
        private Path reportOutputDirectory = Path.of("target/pii-guard");
        private int maxDtoDepth = 5;

        private Builder() {}

        /** Sets the packages to scan. Varargs convenience overload. */
        public Builder basePackages(String... packages) {
            this.basePackages = new ArrayList<>(List.of(packages));
            return this;
        }

        /** Sets the packages to scan from a list. */
        public Builder basePackages(List<String> packages) {
            this.basePackages = new ArrayList<>(packages);
            return this;
        }

        /** When {@code true}, the JUnit 5 extension throws an {@code AssertionError} if findings are found. */
        public Builder failOnFindings(boolean failOnFindings) {
            this.failOnFindings = failOnFindings;
            return this;
        }

        /** Findings below this severity are ignored when {@link #failOnFindings} is {@code true}. */
        public Builder minimumSeverity(Severity minimumSeverity) {
            this.minimumSeverity = minimumSeverity;
            return this;
        }

        /** Directory where the HTML report is written. */
        public Builder reportOutputDirectory(Path reportOutputDirectory) {
            this.reportOutputDirectory = reportOutputDirectory;
            return this;
        }

        /**
         * Maximum recursion depth for DTO field analysis.
         * Must be a positive integer. Defaults to 5.
         */
        public Builder maxDtoDepth(int maxDtoDepth) {
            if (maxDtoDepth < 1) {
                throw new IllegalArgumentException("maxDtoDepth must be at least 1, got: " + maxDtoDepth);
            }
            this.maxDtoDepth = maxDtoDepth;
            return this;
        }

        /** Builds the immutable {@link PiiGuardConfiguration}. */
        public PiiGuardConfiguration build() {
            return new PiiGuardConfiguration(this);
        }
    }
}
