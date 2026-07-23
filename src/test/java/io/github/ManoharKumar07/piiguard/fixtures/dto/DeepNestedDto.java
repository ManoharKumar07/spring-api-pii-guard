package io.github.ManoharKumar07.piiguard.fixtures.dto;

/** Self-referential DTO used to test the max-depth limit. */
public class DeepNestedDto {
    private String value;
    private DeepNestedDto child;
}
