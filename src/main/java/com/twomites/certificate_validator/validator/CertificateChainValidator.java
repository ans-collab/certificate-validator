package com.twomites.certificate_validator.validator;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Component;

@Component
public class CertificateChainValidator {

    /**
     * Validates a server certificate chain against trusted certificates.
     * The first certificate in the list must be the leaf certificate.
     */
    public boolean isValid(
            List<X509Certificate> certificateChain,
            Set<X509Certificate> trustedCertificates) {

        if (certificateChain == null || certificateChain.isEmpty()
                || trustedCertificates == null
                || trustedCertificates.isEmpty()) {
            return false;
        }

        if (certificateChain.stream().anyMatch(certificate -> certificate == null)
                || trustedCertificates.stream()
                        .anyMatch(certificate -> certificate == null)) {
            return false;
        }

        try {
            X509Certificate leafCertificate = certificateChain.get(0);

            // A certificate explicitly configured as trusted can itself
            // serve as the trust anchor.
            if (trustedCertificates.contains(leafCertificate)) {
                leafCertificate.checkValidity();
                return true;
            }

            Set<TrustAnchor> trustAnchors = new HashSet<>();

            for (X509Certificate trustedCertificate : trustedCertificates) {
                trustAnchors.add(new TrustAnchor(trustedCertificate, null));
            }

            X509CertSelector targetSelector = new X509CertSelector();
            targetSelector.setCertificate(leafCertificate);

            PKIXBuilderParameters parameters =
                    new PKIXBuilderParameters(trustAnchors, targetSelector);

            // Revocation checking is disabled for now.
            // It can be configured separately when CRL/OCSP support is added.
            parameters.setRevocationEnabled(false);

            // Include both server-presented and trusted certificates.
            // This allows PKIX to find intermediate certificates even when
            // the server does not send a complete chain.
            List<X509Certificate> availableCertificates =
                    new ArrayList<>(certificateChain);

            availableCertificates.addAll(trustedCertificates);

            CertStore certStore = CertStore.getInstance(
                    "Collection",
                    new CollectionCertStoreParameters(availableCertificates));

            parameters.addCertStore(certStore);

            // Build the certification path.
            CertPathBuilder builder =
                    CertPathBuilder.getInstance("PKIX");

            builder.build(parameters);

            return true;

        } catch (GeneralSecurityException e) {
            // Includes invalid paths, untrusted issuers, expired certificates,
            // invalid signatures, and other PKIX validation failures.
            return false;
        }
    }
}