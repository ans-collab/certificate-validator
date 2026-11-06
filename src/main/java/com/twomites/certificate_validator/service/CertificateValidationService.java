package com.twomites.certificate_validator.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.springframework.stereotype.Service;

import com.twomites.certificate_validator.model.CertificateDetails;
import com.twomites.certificate_validator.model.CertificateValidationRequest;
import com.twomites.certificate_validator.model.CertificateValidationResult;
import com.twomites.certificate_validator.model.CertificateValidationResponse;
import com.twomites.certificate_validator.model.ConnectionProtocol;
import com.twomites.certificate_validator.retriever.ServerCertificateRetriever;
import com.twomites.certificate_validator.validator.CertificateChainValidator;
import com.twomites.certificate_validator.validator.CertificateExpiryValidator;
import com.twomites.certificate_validator.validator.CertificateSignatureValidator;
import com.twomites.certificate_validator.validator.HostnameValidator;

@Service
public class CertificateValidationService {

    private final ServerCertificateRetriever certificateRetriever;
    private final CertificateExpiryValidator expiryValidator;
    private final CertificateSignatureValidator signatureValidator;
    private final HostnameValidator hostnameValidator;
    private final CertificateChainValidator chainValidator;

    public CertificateValidationService(
            ServerCertificateRetriever certificateRetriever,
            CertificateExpiryValidator expiryValidator,
            CertificateSignatureValidator signatureValidator,
            HostnameValidator hostnameValidator,
            CertificateChainValidator chainValidator) {

        this.certificateRetriever = certificateRetriever;
        this.expiryValidator = expiryValidator;
        this.signatureValidator = signatureValidator;
        this.hostnameValidator = hostnameValidator;
        this.chainValidator = chainValidator;
    }

    public CertificateValidationResponse validate(
            CertificateValidationRequest request)
            throws IOException, GeneralSecurityException {

        validateRequest(request);

        String host = request.host();
        ConnectionProtocol protocol = request.protocol();

        int port = resolvePort(request);

        // 1. Retrieve the certificates presented by the server.
        X509Certificate[] certificates =
                certificateRetriever.retrieve(host, port, protocol);

        if (certificates == null || certificates.length == 0) {
            throw new IOException(
                    "The server did not present any certificates.");
        }

        List<X509Certificate> certificateChain =
                Arrays.asList(certificates);

        // 2. Load the JVM's trusted certificates.
        Set<X509Certificate> trustedCertificates =
                loadTrustedCertificates();

        // 3. Validate certificate expiration.
        boolean expiryValid = certificateChain.stream()
                .allMatch(expiryValidator::isValid);

        // 4. Validate certificate signatures.
        boolean signatureValid =
                isSignatureValid(certificateChain, trustedCertificates);

        // 5. Validate hostname against the leaf certificate.
        X509Certificate leafCertificate = certificates[0];

        boolean hostnameValid =
                hostnameValidator.isValid(leafCertificate, host);

        // 6. Validate the certificate chain.
        boolean chainValid = chainValidator.isValid(
                certificateChain,
                trustedCertificates);

        // 7. Build certificate information for the API response.
        List<CertificateDetails> certificateDetails =
                certificateChain.stream()
                        .map(this::toCertificateDetails)
                        .toList();

        CertificateValidationResult result =
                new CertificateValidationResult(
                        expiryValid,
                        signatureValid,
                        hostnameValid,
                        chainValid,
                        certificateDetails);


        String message = buildMessage(result);

        // 8. Return the final response.
        return new CertificateValidationResponse(
                host,
                port,
                protocol,
                result.isValid(),
                result.expiryValid(),
                result.signatureValid(),
                result.hostnameValid(),
                result.chainValid(),
                message,
                result.certificates());
    }

    private boolean isSignatureValid(
            List<X509Certificate> certificateChain,
            Set<X509Certificate> trustedCertificates) {

        List<X509Certificate> possibleIssuers =
                new ArrayList<>(certificateChain);

        possibleIssuers.addAll(trustedCertificates);

        for (X509Certificate certificate : certificateChain) {

            boolean signatureVerified = false;

            for (X509Certificate issuer : possibleIssuers) {

                if (!certificate.getIssuerX500Principal()
                        .equals(issuer.getSubjectX500Principal())) {
                    continue;
                }

                PublicKey issuerPublicKey = issuer.getPublicKey();

                if (signatureValidator.isValid(
                        certificate, issuerPublicKey)) {

                    signatureVerified = true;
                    break;
                }
            }

            if (!signatureVerified) {
                return false;
            }
        }

        return true;
    }

    private Set<X509Certificate> loadTrustedCertificates()
            throws GeneralSecurityException {

        Set<X509Certificate> trustedCertificates = new HashSet<>();

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());

        // null means use the JVM's default trust store.
        trustManagerFactory.init((KeyStore) null);

        for (TrustManager trustManager :
                trustManagerFactory.getTrustManagers()) {

            if (trustManager instanceof X509TrustManager x509TrustManager) {

                trustedCertificates.addAll(
                        Arrays.asList(
                                x509TrustManager.getAcceptedIssuers()));
            }
        }

        if (trustedCertificates.isEmpty()) {
            throw new GeneralSecurityException(
                    "No trusted certificates were found.");
        }

        return trustedCertificates;
    }

    private CertificateDetails toCertificateDetails(
            X509Certificate certificate) {

        return new CertificateDetails(
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(16),
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant());
    }

    private String buildMessage(CertificateValidationResult result) {

        if (result.isValid()) {
            return "Certificate validation successful.";
        }

        List<String> failures = new ArrayList<>();

        if (!result.expiryValid()) {
            failures.add("Certificate expired or not yet valid");
        }

        if (!result.signatureValid()) {
            failures.add("Certificate signature validation failed");
        }

        if (!result.hostnameValid()) {
            failures.add("Hostname does not match certificate");
        }

        if (!result.chainValid()) {
            failures.add("Certificate chain is not trusted");
        }

        return "Certificate validation failed: "
                + String.join(", ", failures) + ".";
    }

    private int resolvePort(CertificateValidationRequest request) {

        Integer requestedPort = request.port();

        if (requestedPort == null
                && request.protocol().getDefaultPort() == -1) {

            throw new IllegalArgumentException(
                    "Port must be specified for generic TLS connections.");
        }

        int port = requestedPort != null
                ? requestedPort
                : request.protocol().getDefaultPort();

        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException(
                    "Port must be between 1 and 65535.");
        }

        return port;
    }

    private void validateRequest(CertificateValidationRequest request) {

        if (request == null) {
            throw new IllegalArgumentException(
                    "Request cannot be null.");
        }

        if (request.host() == null || request.host().isBlank()) {
            throw new IllegalArgumentException(
                    "Host cannot be null or blank.");
        }

        if (request.protocol() == null) {
            throw new IllegalArgumentException(
                    "Protocol cannot be null.");
        }
    }
}
