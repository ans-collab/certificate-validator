package com.twomites.certificate_validator.model;

/**
 * This represents the request sent to the REST API.
 * CertificateValidationRequest
 */
public record CertificateValidationRequest(
        String host,
        Integer port,
        ConnectionProtocol protocol
) {
}


/**
 * {
  "host": "sha256.badssl.com",
  "port": null,
  "protocol": "HTTPS"
}
 */