package io.github.manoharkumar07.piiguard.fixtures.dto;

/** Extends BaseDto to test that inherited fields (id, createdAt) are extracted. */
public class InheritedFieldsDto extends BaseDto {
    private String username;
    private String email;
}
