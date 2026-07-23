package io.github.manoharkumar07.piiguard.fixtures.controllers;

import io.github.manoharkumar07.piiguard.fixtures.dto.FinancialDto;
import io.github.manoharkumar07.piiguard.fixtures.dto.PersonalInfoDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately vulnerable controller exposing financial and personal-info DTOs.
 * Used to test detection of MEDIUM and LOW severity findings (PHONE, DOB, SALARY,
 * ADDRESS, LOCATION, IP, ETHNICITY) and HIGH financial findings (CREDIT_CARD, CVV,
 * BANK_ACCOUNT) that are not covered by VulnerableUserController.
 */
@RestController
@RequestMapping("/api/sensitive")
public class SensitiveDataController {

    @GetMapping("/financial")
    public FinancialDto getFinancialData() { return null; }

    @GetMapping("/personal")
    public PersonalInfoDto getPersonalInfo() { return null; }
}
