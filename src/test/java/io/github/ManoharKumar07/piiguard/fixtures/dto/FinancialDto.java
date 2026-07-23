package io.github.ManoharKumar07.piiguard.fixtures.dto;

/**
 * Fixture DTO that intentionally exposes financial and credential fields.
 *
 * <p>Expected findings from this DTO:
 * <ul>
 *   <li>{@code creditCard}    — HIGH   (CREDIT_CARD_EXPOSURE)</li>
 *   <li>{@code cvv}           — HIGH   (CVV_EXPOSURE)</li>
 *   <li>{@code accountNumber} — HIGH   (BANK_ACCOUNT_EXPOSURE)</li>
 *   <li>{@code otp}           — CRITICAL (OTP_EXPOSURE)</li>
 * </ul>
 */
public class FinancialDto {

    private String creditCard;
    private String cvv;
    private String accountNumber;
    private String otp;
    private String transactionId;   // safe — no PII match expected
    private String currency;        // safe
}
