package com.twomites.certificate_validator.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/certificates_ui")
public class CertificateLandingPageUIController {

    @GetMapping
    public String landingPage() {
        return "redirect:/certificates.html";
    }
}