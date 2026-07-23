package io.github.manoharkumar07.piiguard.fixtures.controllers;

import io.github.manoharkumar07.piiguard.fixtures.dto.CircularADto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Fixture controller that returns a DTO involved in a circular reference.
 * Used to verify that the analysis engine handles circular DTO graphs without
 * throwing a {@link StackOverflowError}.
 *
 * <p>{@code CircularADto} references {@code CircularBDto} which references
 * {@code CircularADto} back. None of their fields match PII patterns, so this
 * endpoint should produce zero findings.
 */
@RestController
@RequestMapping("/api/circular")
public class CircularController {

    @GetMapping
    public CircularADto getCircularData() { return null; }
}
