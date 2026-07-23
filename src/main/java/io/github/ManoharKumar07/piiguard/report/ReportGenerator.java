package io.github.ManoharKumar07.piiguard.report;

import io.github.ManoharKumar07.piiguard.engine.AnalysisResult;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Strategy interface for generating a report from an {@link AnalysisResult}.
 *
 * <p>The default implementation is {@link HtmlReportGenerator}, which produces a
 * self-contained HTML file. Consumers who need a different format (JSON, CSV, PDF)
 * can implement this interface and supply it to the engine.
 */
public interface ReportGenerator {

    /**
     * Generates a report from the given analysis result and writes it to the specified directory.
     *
     * @param result          the analysis result to report on
     * @param outputDirectory directory in which the report file will be created;
     *                        created automatically if it does not exist
     * @return path to the generated report file
     * @throws IOException if the report cannot be written to disk
     */
    Path generate(AnalysisResult result, Path outputDirectory) throws IOException;
}
