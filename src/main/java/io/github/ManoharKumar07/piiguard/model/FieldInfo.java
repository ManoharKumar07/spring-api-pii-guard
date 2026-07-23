package io.github.ManoharKumar07.piiguard.model;

import java.util.List;

/**
 * Immutable representation of a single field discovered during DTO analysis.
 *
 * @param name        Java field name as declared in the source
 * @param jsonName    Serialized name (from {@code @JsonProperty}, or same as {@code name} if absent)
 * @param typeName    Full generic type string (e.g. {@code List<AddressDto>})
 * @param isCollection {@code true} if the field is a collection or map type
 * @param nestedDto   Recursively extracted DTO info; {@code null} for terminal/scalar types
 * @param annotations Simple names of all annotations present on this field
 */
public record FieldInfo(
        String name,
        String jsonName,
        String typeName,
        boolean isCollection,
        DtoInfo nestedDto,
        List<String> annotations
) {}
