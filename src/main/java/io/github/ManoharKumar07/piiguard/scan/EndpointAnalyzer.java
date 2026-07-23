package io.github.ManoharKumar07.piiguard.scan;

import io.github.ManoharKumar07.piiguard.model.DtoInfo;
import io.github.ManoharKumar07.piiguard.model.FieldInfo;
import io.github.ManoharKumar07.piiguard.model.ScannedEndpoint;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.*;

/**
 * Extracts {@link ScannedEndpoint} metadata from a {@code @RestController} class.
 *
 * <h2>Path resolution</h2>
 * The full endpoint path is the combination of the class-level {@code @RequestMapping}
 * prefix and the method-level mapping annotation path.
 *
 * <h2>Generic type resolution</h2>
 * Return types are unwrapped to locate the actual response DTO:
 * {@code ResponseEntity<UserDto>} → {@code UserDto},
 * {@code List<UserDto>} → {@code UserDto},
 * {@code Map<String, UserDto>} → {@code UserDto}.
 */
public final class EndpointAnalyzer {

    private final DtoFieldExtractor dtoFieldExtractor;
    private final int maxDtoDepth;

    /**
     * @param dtoFieldExtractor extractor used for response and request body DTOs
     * @param maxDtoDepth       maximum DTO recursion depth passed to the extractor
     */
    public EndpointAnalyzer(DtoFieldExtractor dtoFieldExtractor, int maxDtoDepth) {
        this.dtoFieldExtractor = dtoFieldExtractor;
        this.maxDtoDepth = maxDtoDepth;
    }

    /**
     * Analyses all mapped methods on {@code controllerClass} and returns one
     * {@link ScannedEndpoint} per mapping annotation found.
     *
     * @param controllerClass a class annotated with {@code @RestController}
     * @return immutable list of discovered endpoints, never {@code null}
     */
    public List<ScannedEndpoint> analyze(Class<?> controllerClass) {
        String basePath = extractBasePath(controllerClass);
        List<ScannedEndpoint> endpoints = new ArrayList<>();

        for (Method method : controllerClass.getMethods()) {
            MappingInfo mappingInfo = extractMappingInfo(method);
            if (mappingInfo == null) continue;

            String fullPath = joinPaths(basePath, mappingInfo.path());
            DtoInfo responseDto = extractResponseDto(method);
            DtoInfo requestDto = extractRequestBodyDto(method);
            List<FieldInfo> pathVariables = extractPathVariables(method);
            List<FieldInfo> queryParameters = extractQueryParameters(method);

            endpoints.add(new ScannedEndpoint(
                    mappingInfo.httpMethod(),
                    fullPath,
                    controllerClass.getName(),
                    method.getName(),
                    responseDto,
                    requestDto,
                    Collections.unmodifiableList(pathVariables),
                    Collections.unmodifiableList(queryParameters)
            ));
        }

        return Collections.unmodifiableList(endpoints);
    }

    // -----------------------------------------------------------------------
    // Path extraction
    // -----------------------------------------------------------------------

    private String extractBasePath(Class<?> controllerClass) {
        RequestMapping rm = controllerClass.getAnnotation(RequestMapping.class);
        if (rm != null) {
            String[] paths = rm.value().length > 0 ? rm.value() : rm.path();
            if (paths.length > 0 && !paths[0].isEmpty()) {
                return paths[0];
            }
        }
        return "";
    }

    private MappingInfo extractMappingInfo(Method method) {
        GetMapping get = method.getAnnotation(GetMapping.class);
        if (get != null) {
            return new MappingInfo("GET", firstPath(get.value(), get.path()));
        }
        PostMapping post = method.getAnnotation(PostMapping.class);
        if (post != null) {
            return new MappingInfo("POST", firstPath(post.value(), post.path()));
        }
        PutMapping put = method.getAnnotation(PutMapping.class);
        if (put != null) {
            return new MappingInfo("PUT", firstPath(put.value(), put.path()));
        }
        DeleteMapping delete = method.getAnnotation(DeleteMapping.class);
        if (delete != null) {
            return new MappingInfo("DELETE", firstPath(delete.value(), delete.path()));
        }
        PatchMapping patch = method.getAnnotation(PatchMapping.class);
        if (patch != null) {
            return new MappingInfo("PATCH", firstPath(patch.value(), patch.path()));
        }
        RequestMapping rm = method.getAnnotation(RequestMapping.class);
        if (rm != null) {
            String httpMethod = rm.method().length > 0 ? rm.method()[0].name() : "GET";
            return new MappingInfo(httpMethod, firstPath(rm.value(), rm.path()));
        }
        return null;
    }

    private static String firstPath(String[] value, String[] path) {
        if (value.length > 0) return value[0];
        if (path.length > 0) return path[0];
        return "";
    }

    private static String joinPaths(String base, String path) {
        if (base.isEmpty() && path.isEmpty()) return "/";
        if (base.isEmpty()) return path.startsWith("/") ? path : "/" + path;
        if (path.isEmpty()) return base;
        boolean baseEnds = base.endsWith("/");
        boolean pathStarts = path.startsWith("/");
        if (baseEnds && pathStarts) return base + path.substring(1);
        if (!baseEnds && !pathStarts) return base + "/" + path;
        return base + path;
    }

    // -----------------------------------------------------------------------
    // Response / request body DTO extraction
    // -----------------------------------------------------------------------

    private DtoInfo extractResponseDto(Method method) {
        Class<?> responseClass = unwrapType(method.getGenericReturnType());
        if (responseClass == null || responseClass == void.class || responseClass == Void.class) {
            return null;
        }
        if (isScalarType(responseClass)) {
            return DtoInfo.terminal(responseClass);
        }
        return dtoFieldExtractor.extract(responseClass, maxDtoDepth);
    }

    private DtoInfo extractRequestBodyDto(Method method) {
        for (Parameter param : method.getParameters()) {
            if (param.getAnnotation(RequestBody.class) != null) {
                Class<?> paramClass = unwrapType(param.getParameterizedType());
                if (paramClass != null && !isScalarType(paramClass)) {
                    return dtoFieldExtractor.extract(paramClass, maxDtoDepth);
                }
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Path variable / query parameter extraction
    // -----------------------------------------------------------------------

    private List<FieldInfo> extractPathVariables(Method method) {
        List<FieldInfo> result = new ArrayList<>();
        for (Parameter param : method.getParameters()) {
            PathVariable pv = param.getAnnotation(PathVariable.class);
            if (pv != null) {
                String name = resolveParamName(pv.value(), pv.name(), param.getName());
                result.add(new FieldInfo(name, name, param.getType().getSimpleName(),
                        false, null, List.of("PathVariable"), List.of()));
            }
        }
        return result;
    }

    private List<FieldInfo> extractQueryParameters(Method method) {
        List<FieldInfo> result = new ArrayList<>();
        for (Parameter param : method.getParameters()) {
            RequestParam rp = param.getAnnotation(RequestParam.class);
            if (rp != null) {
                String name = resolveParamName(rp.value(), rp.name(), param.getName());
                result.add(new FieldInfo(name, name, param.getType().getSimpleName(),
                        false, null, List.of("RequestParam"), List.of()));
            }
        }
        return result;
    }

    /** Resolves a parameter name from annotation value/name attributes, falling back to the Java name. */
    private static String resolveParamName(String value, String name, String fallback) {
        if (!value.isEmpty()) return value;
        if (!name.isEmpty()) return name;
        return fallback;
    }

    // -----------------------------------------------------------------------
    // Generic type unwrapping
    // -----------------------------------------------------------------------

    /**
     * Unwraps wrapper types to find the actual DTO class:
     * {@code ResponseEntity<T>} → {@code T},
     * {@code List<T>} → {@code T},
     * {@code Map<K,V>} → {@code V},
     * {@code T} → {@code T}.
     */
    private Class<?> unwrapType(Type type) {
        if (type instanceof Class<?> clazz) {
            return clazz;
        }
        if (type instanceof ParameterizedType pt) {
            Class<?> rawClass = (Class<?>) pt.getRawType();
            if (ResponseEntity.class.isAssignableFrom(rawClass)) {
                Type[] args = pt.getActualTypeArguments();
                if (args.length > 0) return unwrapType(args[0]);
                return null;
            }
            if (Collection.class.isAssignableFrom(rawClass)) {
                Type[] args = pt.getActualTypeArguments();
                if (args.length > 0) return unwrapType(args[0]);
                return null;
            }
            if (Map.class.isAssignableFrom(rawClass)) {
                Type[] args = pt.getActualTypeArguments();
                if (args.length > 1) return unwrapType(args[1]);
                return null;
            }
            return rawClass;
        }
        return null;
    }

    /** Returns {@code true} for types that do not need DTO field analysis. */
    private boolean isScalarType(Class<?> clazz) {
        if (clazz == null || clazz.isPrimitive()) return true;
        String name = clazz.getName();
        return name.startsWith("java.lang")
                || name.startsWith("java.time")
                || name.startsWith("java.math")
                || clazz == java.util.UUID.class
                || clazz == java.util.Date.class
                || Collection.class.isAssignableFrom(clazz)
                || Map.class.isAssignableFrom(clazz)
                || clazz.isEnum();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private record MappingInfo(String httpMethod, String path) {}
}
