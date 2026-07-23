package io.github.manoharkumar07.piiguard.fixtures.dto;

/**
 * Fixture DTO that intentionally exposes personal, biometric, and location fields.
 *
 * <p>Expected findings from this DTO:
 * <ul>
 *   <li>{@code nationalId}   — HIGH   (NATIONAL_ID_EXPOSURE)</li>
 *   <li>{@code phone}        — MEDIUM (PHONE_EXPOSURE)</li>
 *   <li>{@code dateOfBirth}  — MEDIUM (DOB_EXPOSURE)</li>
 *   <li>{@code diagnosis}    — MEDIUM (HEALTH_EXPOSURE)</li>
 *   <li>{@code fingerprint}  — MEDIUM (BIOMETRIC_EXPOSURE)</li>
 *   <li>{@code gender}       — MEDIUM (GENDER_EXPOSURE)</li>
 *   <li>{@code salary}       — MEDIUM (SALARY_EXPOSURE)</li>
 *   <li>{@code address}      — LOW    (ADDRESS_EXPOSURE)</li>
 *   <li>{@code latitude}     — LOW    (LOCATION_EXPOSURE)</li>
 *   <li>{@code ipAddress}    — LOW    (IP_ADDRESS_EXPOSURE)</li>
 *   <li>{@code ethnicity}    — LOW    (ETHNICITY_EXPOSURE)</li>
 * </ul>
 */
public class PersonalInfoDto {

    private String nationalId;
    private String phone;
    private String dateOfBirth;
    private String diagnosis;
    private String fingerprint;
    private String gender;
    private String salary;
    private String address;
    private String latitude;
    private String ipAddress;
    private String ethnicity;
    private String profilePicture;  // safe — no PII match expected
    private String displayName;     // safe
}
