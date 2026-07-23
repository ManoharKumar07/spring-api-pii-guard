package io.github.ManoharKumar07.piiguard.fixtures.controllers;

import io.github.ManoharKumar07.piiguard.fixtures.dto.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Deliberately vulnerable controller used as a test fixture.
 * Contains endpoints that expose PII fields in response bodies.
 */
@RestController
@RequestMapping("/api/users")
public class VulnerableUserController {

    @GetMapping("/{id}")
    public UserWithPasswordDto getUser(@PathVariable("id") Long id) {
        return null;
    }

    @GetMapping
    public List<UserWithSsnDto> getAllUsers() {
        return null;
    }

    @PostMapping
    public ResponseEntity<UserTokenDto> createUser(@RequestBody CreateUserRequest request) {
        return null;
    }

    @PutMapping("/{id}")
    public UserWithPasswordDto updateUser(@PathVariable("id") Long id,
                                          @RequestBody CreateUserRequest request) {
        return null;
    }

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable("id") Long id) {
    }
}
