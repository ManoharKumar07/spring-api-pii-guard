package io.github.ManoharKumar07.piiguard.fixtures.dto;

/** Part of a circular reference pair (B → A → B) used to test cycle detection. */
public class CircularBDto {
    private Long id;
    private CircularADto owner;
}
