package io.github.manoharkumar07.piiguard.fixtures.dto;

/** DTO that deliberately exposes credential fields — should trigger CRITICAL findings. */
public class UserWithPasswordDto {
    private Long id;
    private String username;
    private String password;
    private String passwordHash;
}
