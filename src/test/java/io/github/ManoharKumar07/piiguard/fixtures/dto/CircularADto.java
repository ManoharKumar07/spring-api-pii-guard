package io.github.ManoharKumar07.piiguard.fixtures.dto;

/** Part of a circular reference pair (A → B → A) used to test cycle detection. */
public class CircularADto {
    private Long id;
    private String name;
    private CircularBDto related;
}
