package com.twomites.certificate_validator.controller;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.twomites.certificate_validator.model.CertificateValidationRequest;
import com.twomites.certificate_validator.model.CertificateValidationResponse;
import com.twomites.certificate_validator.model.ConnectionProtocol;
import com.twomites.certificate_validator.service.CertificateValidationService;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    private final CertificateValidationService validationService;

    public CertificateController(
            CertificateValidationService validationService) {
        this.validationService = validationService;
    }

    @GetMapping("/validate")
    public ResponseEntity<CertificateValidationResponse> validate(
            @RequestParam("url") String url) {

        try {

            URI uri = URI.create(url);

            String scheme = uri.getScheme();
            String host = uri.getHost();

            System.out.println("URL: " + url);
            System.out.println("Scheme: " + scheme);
            System.out.println("Host: " + host);
            
            if (scheme == null || host == null) {
                throw new IllegalArgumentException(
                        "A valid URL with a hostname is required");
            }

            ConnectionProtocol protocol = resolveProtocol(scheme);

            System.out.println("Protocol: " + protocol);

             // Null allows the service to resolve the default port
            Integer port = uri.getPort() == -1
                    ? null
                    : uri.getPort();

            CertificateValidationRequest request =
                    new CertificateValidationRequest(
                            host,
                            port,
                            protocol);

            CertificateValidationResponse response =
                    validationService.validate(request);

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    e.getMessage(),
                    e);

        } catch (IOException | GeneralSecurityException e) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "Unable to retrieve or validate the server certificate: "
                            + e.getMessage(),
                    e);
        }
    } //validate

    private ConnectionProtocol resolveProtocol(String scheme) {

        return switch (scheme.toLowerCase(Locale.ROOT)) {
            case "https" -> ConnectionProtocol.HTTPS;
            case "tls" -> ConnectionProtocol.TLS;
            case "smtps" -> ConnectionProtocol.SMTPS;
            case "smtp+starttls" -> ConnectionProtocol.SMTP_STARTTLS;

            default -> throw new IllegalArgumentException(
                    "Unsupported URL scheme: " + scheme);
        };
    } //resolveProtocol
}
