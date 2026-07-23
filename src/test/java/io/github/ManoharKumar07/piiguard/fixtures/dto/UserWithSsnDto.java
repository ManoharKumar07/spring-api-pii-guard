package io.github.ManoharKumar07.piiguard.fixtures.dto;

/** DTO that deliberately exposes government-ID fields — should trigger HIGH findings. */
public class UserWithSsnDto {
    private Long id;
    private String name;
    private String socialSecurityNumber;
    private String aadhaarNumber;
}
