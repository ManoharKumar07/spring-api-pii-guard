package io.github.manoharkumar07.piiguard.fixtures.dto;

import java.math.BigDecimal;

/** Safe product DTO — should produce no PII findings. */
public class ProductDto {
    private Long id;
    private String name;
    private String description;
    private BigDecimal price;
    private String category;
}
