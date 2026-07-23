package io.github.ManoharKumar07.piiguard.scan;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.ManoharKumar07.piiguard.model.DtoInfo;
import io.github.ManoharKumar07.piiguard.model.FieldInfo;
import io.github.ManoharKumar07.piiguard.suppress.PiiGuardSuppress;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Recursively extracts field metadata from DTO classes using Java Reflection.
 *
 * <h3>Cycle detection</h3>
 * A {@code visited} set is threaded through the recursion. When a class is encountered
 * a second time (e.g. {@code User} → {@code Address} → {@code User}), a terminal
 * {@link DtoInfo} with no fields is returned, stopping the recursion.
 *
 * <h3>Depth limiting</h3>
 * The {@code maxDepth} parameter caps the recursion depth regardless of cycles.
 * A default of 5 is sufficient for real-world DTOs.
 *
 * <h3>Inherited fields</h3>
 * {@link #getAllFields(Class)} walks the superclass hierarchy so fields declared
 * in parent classes (e.g. {@code BaseDto}) are included.
 */
public final class DtoFieldExtractor {

    /**
     * Extracts DTO metadata up to {@code maxDepth} levels of nesting.
     *
     * @param dtoClass class to analyse
     * @param maxDepth maximum recursion depth (must be &gt;= 1)
     * @return extracted DTO info, never {@code null}
     */
    public DtoInfo extract(Class<?> dtoClass, int maxDepth) {
        return extract(dtoClass, maxDepth, new HashSet<>());
    }

    private DtoInfo extract(Class<?> dtoClass, int remainingDepth, Set<Class<?>> visited) {
        if (remainingDepth <= 0 || visited.contains(dtoClass) || isTerminalType(dtoClass)) {
            return DtoInfo.terminal(dtoClass);
        }
        visited.add(dtoClass);

        List<FieldInfo> fields = new ArrayList<>();
        for (Field field : getAllFields(dtoClass)) {
            if (field.isSynthetic()) continue;
            // Pass a copy of visited so sibling fields are analysed independently
            fields.add(analyzeField(field, remainingDepth - 1, new HashSet<>(visited)));
        }
        return new DtoInfo(dtoClass.getName(), Collections.unmodifiableList(fields));
    }

    private FieldInfo analyzeField(Field field, int remainingDepth, Set<Class<?>> visited) {
        String name = field.getName();
        String jsonName = resolveJsonName(field);
        String typeName = field.getGenericType().getTypeName();
        boolean isCollectionField = isCollectionType(field.getType());

        List<String> annotationNames = Arrays.stream(field.getAnnotations())
                .map(a -> a.annotationType().getSimpleName())
                .collect(Collectors.toUnmodifiableList());

        List<String> suppressedRules = resolveSuppressedRules(field);

        // Resolve the effective element type (unwraps List<T> → T, Map<K,V> → V)
        Class<?> elementType = resolveEffectiveType(field.getGenericType());
        DtoInfo nestedDto = null;
        if (elementType != null && !isTerminalType(elementType)) {
            nestedDto = extract(elementType, remainingDepth, visited);
        }

        return new FieldInfo(name, jsonName, typeName, isCollectionField, nestedDto, annotationNames, suppressedRules);
    }

    /**
     * Resolves the serialised JSON name for a field.
     * Uses {@code @JsonProperty("name")} if present, otherwise falls back to the Java field name.
     */
    private String resolveJsonName(Field field) {
        JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
        if (jsonProperty != null && !jsonProperty.value().isEmpty()) {
            return jsonProperty.value();
        }
        return field.getName();
    }

    /**
     * Reads any {@code @PiiGuardSuppress} annotation on the field and returns the list of
     * suppressed rule IDs.
     * <ul>
     *   <li>If the annotation is absent, returns an empty list.</li>
     *   <li>If {@code rules()} is empty, returns {@code ["*"]} meaning all rules are suppressed.</li>
     *   <li>Otherwise, returns the explicit rule IDs listed in the annotation.</li>
     * </ul>
     */
    private List<String> resolveSuppressedRules(Field field) {
        PiiGuardSuppress suppress = field.getAnnotation(PiiGuardSuppress.class);
        if (suppress == null) {
            return List.of();
        }
        if (suppress.rules().length == 0) {
            return List.of("*");
        }
        return List.of(suppress.rules());
    }

    /**
     * Resolves the element type of a generic type.
     * <ul>
     *   <li>{@code List<T>}, {@code Set<T>} → {@code T}</li>
     *   <li>{@code Map<K, V>} → {@code V}</li>
     *   <li>{@code T} → {@code T}</li>
     * </ul>
     */
    private Class<?> resolveEffectiveType(Type type) {
        if (type instanceof Class<?> clazz) {
            return clazz;
        }
        if (type instanceof ParameterizedType pt) {
            Class<?> rawClass = (Class<?>) pt.getRawType();
            if (Collection.class.isAssignableFrom(rawClass) || Iterable.class.isAssignableFrom(rawClass)) {
                Type[] args = pt.getActualTypeArguments();
                if (args.length > 0) {
                    return resolveEffectiveType(args[0]);
                }
            }
            if (Map.class.isAssignableFrom(rawClass)) {
                Type[] args = pt.getActualTypeArguments();
                if (args.length > 1) {
                    return resolveEffectiveType(args[1]);
                }
            }
            // Other parameterised types: return the raw class
            return rawClass;
        }
        return null;
    }

    /**
     * Returns {@code true} for types whose internal fields are not relevant to PII analysis:
     * primitives, {@code java.lang.*}, {@code java.time.*}, {@code java.math.*},
     * {@link UUID}, {@link Date}, enums, arrays, and collection/map types.
     */
    private boolean isTerminalType(Class<?> clazz) {
        if (clazz == null || clazz.isPrimitive() || clazz.isArray()) return true;
        String name = clazz.getName();
        return name.startsWith("java.lang")
                || name.startsWith("java.time")
                || name.startsWith("java.math")
                || clazz == UUID.class
                || clazz == Date.class
                || clazz == Calendar.class
                || Collection.class.isAssignableFrom(clazz)
                || Map.class.isAssignableFrom(clazz)
                || clazz.isEnum();
    }

    /** Returns {@code true} for {@link Collection}, {@link Map}, and array types. */
    private boolean isCollectionType(Class<?> clazz) {
        return Collection.class.isAssignableFrom(clazz)
                || Map.class.isAssignableFrom(clazz)
                || clazz.isArray();
    }

    /**
     * Returns all fields declared in {@code clazz} and every superclass up to (but not including)
     * {@link Object}. Fields are ordered from subclass to superclass.
     */
    private List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            fields.addAll(Arrays.asList(current.getDeclaredFields()));
            current = current.getSuperclass();
        }
        return fields;
    }
}
