package com.twomites.certificate_validator.validator;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.springframework.stereotype.Component;



@Component 
public class CertificateSignatureValidator {

    /**
     * verify certificate signatures; 
     * verify certificate has not been tampered with and was signed by expected issuer
     */

    public boolean isValid (X509Certificate certificate,
            PublicKey issuerPublicKey) {

        if (certificate == null || issuerPublicKey == null) {
            throw new IllegalArgumentException (
                    "Certificate and issuer public key cannot be null"
            );
        }

        try { 
            certificate.verify(issuerPublicKey);
            return true;
        } catch (Exception e) {
            return false;
        }

    }
}