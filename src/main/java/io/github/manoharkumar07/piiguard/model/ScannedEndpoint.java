package io.github.manoharkumar07.piiguard.model;

import java.util.List;

/**
 * Immutable representation of a single REST endpoint discovered by the scanner.
 *
 * @param httpMethod      HTTP verb (GET, POST, PUT, DELETE, PATCH)
 * @param path            Full path including class-level prefix (e.g. {@code /api/users/{id}})
 * @param controllerClass Fully qualified name of the {@code @RestController} class
 * @param methodName      Java method name on the controller
 * @param responseDto     Analysed response DTO; {@code null} for void endpoints
 * @param requestDto      Analysed {@code @RequestBody} DTO; {@code null} when absent
 * @param pathVariables   Parameters annotated with {@code @PathVariable}
 * @param queryParameters Parameters annotated with {@code @RequestParam}
 */
public record ScannedEndpoint(
        String httpMethod,
        String path,
        String controllerClass,
        String methodName,
        DtoInfo responseDto,
        DtoInfo requestDto,
        List<FieldInfo> pathVariables,
        List<FieldInfo> queryParameters
) {}
