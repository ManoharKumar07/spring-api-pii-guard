package io.github.manoharkumar07.piiguard.fixtures.controllers;

import io.github.manoharkumar07.piiguard.fixtures.dto.ProductDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Safe product controller used as a test fixture.
 * Should produce no PII findings — all DTOs contain only non-sensitive fields.
 */
@RestController
@RequestMapping("/api/products")
public class SafeProductController {

    @GetMapping("/{id}")
    public ProductDto getProduct(@PathVariable("id") Long id) {
        return null;
    }

    @GetMapping
    public ResponseEntity<List<ProductDto>> listProducts(
            @RequestParam(value = "page", defaultValue = "0") int page) {
        return null;
    }

    @PostMapping
    public ResponseEntity<ProductDto> createProduct(@RequestBody ProductDto product) {
        return null;
    }
}
