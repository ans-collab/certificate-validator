package com.twomites.certificate_validator.validator;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import org.springframework.stereotype.Component;

@Component 
public class CertificateExpiryValidator {

    /**
     * validity-date checks
     */

    public boolean isValid(X509Certificate certificate) {
        if(certificate == null) {
            throw new IllegalArgumentException (
                    "Certificate cannot be null"
            );
        }
        try {
            certificate.checkValidity();
            return true;
        } catch (CertificateExpiredException | 
                CertificateNotYetValidException e ) {
            return false;
        }
    }

}