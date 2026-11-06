package com.twomites.certificate_validator.model;

import java.util.List;
import org.springframework.boot.info.SslInfo.CertificateInfo;

/**
 * This represents the internal validation results produced the service
 */
public record CertificateValidationResult(
        boolean expiryValid,
        boolean signatureValid,
        boolean hostnameValid,
        boolean chainValid,
        List<CertificateDetails> certificates
) {
    public boolean isValid() {
        return expiryValid
                && signatureValid
                && hostnameValid
                && chainValid;
    }
}
