package com.twomites.certificate_validator.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.twomites.certificate_validator.testdata.CertificateTestData;
import com.twomites.certificate_validator.testdata.CertificateTestData.BadSslTestCase;
import com.twomites.certificate_validator.testdata.BadSslCertificateTestData;

class CertificateSignatureValidatorTest {

    private CertificateSignatureValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CertificateSignatureValidator();
    }

    /**
     * Provides centralized BadSSL test scenarios.
     */
    static Stream<BadSslTestCase> badSslTestCases() {
        return CertificateTestData.getBadSslTestCases().stream();
    }

    /**
     * Validates the certificate signature using the issuer's public key.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("badSslTestCases")
    void validateCertificateSignature(BadSslTestCase testCase)
            throws Exception {

        X509Certificate[] chain =
                BadSslCertificateTestData.getCertificateChain(testCase);

        X509Certificate certificate = chain[0];

        // For a self-signed certificate, use its own public key.
        // Otherwise, use the next certificate in the chain.
        PublicKey issuerPublicKey =
                chain.length > 1
                        ? chain[1].getPublicKey()
                        : certificate.getPublicKey();

        boolean result = validator.isValid(
                certificate,
                issuerPublicKey
        );

        assertEquals(
                testCase.expectedSignatureValid(),
                result,
                testCase.name()
        );
    }
}
