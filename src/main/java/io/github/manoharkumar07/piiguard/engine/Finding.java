package io.github.manoharkumar07.piiguard.engine;

import io.github.manoharkumar07.piiguard.model.Severity;

/**
 * Immutable result of a single PII detection rule match on a field within an endpoint.
 *
 * @param ruleId          unique identifier of the rule that produced this finding
 * @param severity        classification of how critical the exposure is
 * @param piiCategory     human-readable category (e.g. "Credentials", "Government ID")
 * @param fieldName       Java field name as declared in the DTO
 * @param fieldJsonName   serialised name (from {@code @JsonProperty} or same as {@code fieldName})
 * @param dtoClassName    fully qualified name of the DTO class that directly contains the field
 * @param endpointPath    full path of the endpoint (e.g. {@code /api/users/{id}})
 * @param httpMethod      HTTP verb of the endpoint (GET, POST, PUT, DELETE, PATCH)
 * @param controllerClass fully qualified name of the {@code @RestController} class
 * @param message         human-readable description of the finding
 * @param recommendation  actionable suggestion for fixing the exposure
 * @param isInRequestBody {@code true} if the field is part of the {@code @RequestBody} DTO
 * @param isInResponseBody {@code true} if the field is part of the response DTO
 */
public record Finding(
        String ruleId,
        Severity severity,
        String piiCategory,
        String fieldName,
        String fieldJsonName,
        String dtoClassName,
        String endpointPath,
        String httpMethod,
        String controllerClass,
        String message,
        String recommendation,
        boolean isInRequestBody,
        boolean isInResponseBody
) {}
