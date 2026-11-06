package com.twomites.certificate_validator.model;

import java.time.Instant;

/**
 * This contains useful information about each certificate retrieved from the server.
 */
public record CertificateDetails(
        String subject,
        String issuer,
        String serialNumber,
        Instant validFrom,
        Instant validUntil
) {
}