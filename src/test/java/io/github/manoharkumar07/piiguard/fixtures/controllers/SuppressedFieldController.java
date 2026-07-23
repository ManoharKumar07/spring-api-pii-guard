package io.github.manoharkumar07.piiguard.fixtures.controllers;

import io.github.manoharkumar07.piiguard.fixtures.dto.UserWithSuppressedFieldsDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller fixture used to test suppression and @JsonIgnore handling.
 */
@RestController
@RequestMapping("/api/suppressed")
public class SuppressedFieldController {

    @GetMapping("/{id}")
    public UserWithSuppressedFieldsDto getUser(@PathVariable("id") Long id) {
        return null;
    }
}
