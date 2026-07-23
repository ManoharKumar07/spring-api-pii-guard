package io.github.ManoharKumar07.piiguard.rules.patterns;

import java.util.regex.Pattern;

/**
 * Central repository of compiled {@link Pattern} objects used by field-name detection rules.
 *
 * <p>All patterns are applied to a <em>normalised</em> field name:
 * camelCase is converted to snake_case, hyphens become underscores, and the result
 * is lowercased before matching. Pattern matching uses {@link java.util.regex.Matcher#find()}
 * so the pattern only needs to match a substring of the normalised name.
 *
 * <h2>Normalisation examples</h2>
 * <pre>
 *   socialSecurityNumber → social_security_number
 *   passwordHash         → password_hash
 *   aadhaarNumber        → aadhaar_number
 *   cvv                  → cvv
 * </pre>
 */
public final class PiiPatterns {

    private PiiPatterns() {}

    // -----------------------------------------------------------------------
    // CRITICAL — Credentials & Secrets
    // -----------------------------------------------------------------------

    /** Matches password variants: password, passwd, pwd, passphrase, confirm_password, etc. */
    public static final Pattern PASSWORD =
            Pattern.compile("password|passwd|pwd|passphrase");

    /** Matches secret keys and API tokens: secret, api_key, access_token, auth_token, token, etc. */
    public static final Pattern SECRET_KEY =
            Pattern.compile("secret|api_key|apikey|private_key|access_token|auth_token|client_secret|bearer_token|(?<![a-z])token(?![a-z])");

    /** Matches one-time passwords and MFA codes. */
    public static final Pattern OTP =
            Pattern.compile("(?<![a-z])otp(?![a-z])|one_time_password|mfa_code|totp|hotp|verification_code|otp_code");

    // -----------------------------------------------------------------------
    // HIGH — Government IDs
    // -----------------------------------------------------------------------

    /** Matches Social Security Number variants. */
    public static final Pattern SSN =
            Pattern.compile("(?<![a-z])ssn(?![a-z])|social_security");

    /** Matches Aadhaar (Indian national ID) variants. */
    public static final Pattern AADHAAR =
            Pattern.compile("aadhaar|aadhar");

    /** Matches generic government / national identity document fields. */
    public static final Pattern NATIONAL_ID =
            Pattern.compile("national_id|passport_number|driving_license|dl_number|pan_number|tax_id|voter_id|alien_id");

    // -----------------------------------------------------------------------
    // HIGH — Financial
    // -----------------------------------------------------------------------

    /** Matches credit/debit card number fields. */
    public static final Pattern CREDIT_CARD =
            Pattern.compile("credit_card|card_number|card_num|\\bccn\\b|cc_number|debit_card|pan_card_number");

    /** Matches card security codes. */
    public static final Pattern CVV =
            Pattern.compile("\\bcvv\\b|\\bcvc\\b|card_verification|security_code|cvv_code");

    /** Matches bank account and routing information. */
    public static final Pattern BANK_ACCOUNT =
            Pattern.compile("account_number|bank_account|routing_number|\\biban\\b|\\bifsc\\b|sort_code|swift_code");

    // -----------------------------------------------------------------------
    // MEDIUM — Contact Information
    // -----------------------------------------------------------------------

    /** Matches email address fields. */
    public static final Pattern EMAIL =
            Pattern.compile("email|e_mail");

    /** Matches phone and mobile number fields. */
    public static final Pattern PHONE =
            Pattern.compile("phone|mobile|cell_phone|cell_number|\\bfax\\b|telephone");

    // -----------------------------------------------------------------------
    // MEDIUM — Personal Information
    // -----------------------------------------------------------------------

    /** Matches date-of-birth fields. */
    public static final Pattern DATE_OF_BIRTH =
            Pattern.compile("date_of_birth|\\bdob\\b|birth_date|birthday|birth_year");

    /** Matches medical and health-record fields. */
    public static final Pattern HEALTH =
            Pattern.compile("medical_record|health_insurance|diagnosis|prescription|blood_type|patient_id|insurance_number");

    /** Matches biometric data fields. */
    public static final Pattern BIOMETRIC =
            Pattern.compile("fingerprint|biometric|face_id|retina_scan|voice_print|iris_scan");

    /** Matches gender / sex fields. */
    public static final Pattern GENDER =
            Pattern.compile("gender");

    /** Matches salary, income, and wage fields. */
    public static final Pattern SALARY =
            Pattern.compile("\\bsalary\\b|\\bincome\\b|\\bwage\\b|\\bearnings\\b|annual_pay|compensation");

    // -----------------------------------------------------------------------
    // LOW — Location & Network
    // -----------------------------------------------------------------------

    /** Matches physical address fields. */
    public static final Pattern ADDRESS =
            Pattern.compile("\\baddress\\b|street_address|\\bstreet\\b|zip_code|postal_code");

    /** Matches geographic coordinates. */
    public static final Pattern LOCATION =
            Pattern.compile("\\blatitude\\b|\\blongitude\\b|\\bgps\\b|geo_location|coordinates");

    /** Matches IP address fields. */
    public static final Pattern IP_ADDRESS =
            Pattern.compile("ip_address|ip_addr|client_ip|remote_addr|\\bipv4\\b|\\bipv6\\b");

    /** Matches ethnicity and race fields. */
    public static final Pattern ETHNICITY =
            Pattern.compile("ethnicity|\\brace\\b|nationality");
}
