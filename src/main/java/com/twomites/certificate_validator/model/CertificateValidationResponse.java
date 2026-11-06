package com.twomites.certificate_validator.model;

import java.util.List;

/*
This is the object returned by the REST API.
*/
public record CertificateValidationResponse(
        String host,
        int port,
        ConnectionProtocol protocol,
        boolean valid,
        boolean expiryValid,
        boolean signatureValid,
        boolean hostnameValid,
        boolean chainValid,
        String message,
        List<CertificateDetails> certificates
) {
}

/**
 * successful response example:
 * {
  "host": "sha256.badssl.com",
  "port": 443,
  "protocol": "HTTPS",
  "valid": true,
  "expiryValid": true,
  "signatureValid": true,
  "hostnameValid": true,
  "chainValid": true,
  "message": "Certificate validation successful.",
  "certificates": [
    {
      "subject": "CN=sha256.badssl.com",
      "issuer": "CN=Example CA",
      "serialNumber": "123456789",
      "validFrom": "2026-01-01T00:00:00Z",
      "validUntil": "2027-01-01T00:00:00Z"
    }
  ]
}
 */
