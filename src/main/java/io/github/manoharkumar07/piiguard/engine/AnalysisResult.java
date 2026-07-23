package io.github.manoharkumar07.piiguard.engine;

import io.github.manoharkumar07.piiguard.model.ScannedEndpoint;
import io.github.manoharkumar07.piiguard.model.Severity;

import java.time.Instant;
import java.util.List;

/**
 * Immutable result of a complete PII Guard analysis run.
 *
 * @param endpoints  all endpoints discovered during the scan
 * @param findings   all rule matches produced during analysis
 * @param timestamp  when the analysis was performed
 */
public record AnalysisResult(
        List<ScannedEndpoint> endpoints,
        List<Finding> findings,
        Instant timestamp
) {

    /** Total number of findings across all severities. */
    public int totalFindings() {
        return findings.size();
    }

    /** Number of findings with the given severity. */
    public long countBySeverity(Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }

    /**
     * Returns {@code true} if there are any findings at or above {@code minimumSeverity}.
     * Severity is ordered CRITICAL &gt; HIGH &gt; MEDIUM &gt; LOW &gt; INFO.
     */
    public boolean hasFindings(Severity minimumSeverity) {
        return findings.stream()
                .anyMatch(f -> f.severity().ordinal() <= minimumSeverity.ordinal());
    }
}
