package io.github.manoharkumar07.piiguard.model;

import java.util.List;

/**
 * Immutable representation of a DTO class and its analysed fields.
 *
 * @param className Fully qualified class name of the DTO
 * @param fields    Fields extracted from this DTO (may be empty for terminal types)
 */
public record DtoInfo(
        String className,
        List<FieldInfo> fields
) {

    /**
     * Creates a terminal {@code DtoInfo} for scalar/primitive types where field-level
     * analysis is not meaningful (e.g. {@code String}, {@code Long}, {@code LocalDate}).
     *
     * @param clazz the terminal class
     * @return a {@code DtoInfo} with no fields
     */
    public static DtoInfo terminal(Class<?> clazz) {
        return new DtoInfo(clazz.getName(), List.of());
    }
}
