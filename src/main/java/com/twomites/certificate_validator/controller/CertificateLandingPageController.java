package com.twomites.certificate_validator.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/certificates")
public class CertificateLandingPageController {

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getMessage() throws IOException {
    ClassPathResource resource =
            new ClassPathResource("messages/certificates.txt");

    String message = resource.getContentAsString(StandardCharsets.UTF_8);
    return ResponseEntity.ok(message);
}
}