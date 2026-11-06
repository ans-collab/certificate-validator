package com.twomites.certificate_validator.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.twomites.certificate_validator.testdata.BadSslCertificateTestData;
import com.twomites.certificate_validator.testdata.CertificateTestData;
import com.twomites.certificate_validator.testdata.CertificateTestData.BadSslTestCase;

public class HostnameValidatorTest {

   private HostnameValidator validator;

    @BeforeEach
    void setUp() {
        validator = new HostnameValidator();
    }

    /**
     * Provides centralized BadSSL test scenarios.
     */
    static Stream<BadSslTestCase> badSslTestCases() {
        return CertificateTestData.getBadSslTestCases().stream();
    }

    /**
     * Validates the certificate hostname against the expected hostname.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("badSslTestCases")
    void validateHostname(BadSslTestCase testCase)
            throws Exception {

        X509Certificate certificate =
                BadSslCertificateTestData
                        .getCertificateChain(testCase)[0];

        boolean result = validator.isValid(
                certificate,
                testCase.hostname()
        );

        assertEquals(
                testCase.expectedHostnameValid(),
                result,
                testCase.name()
        );
    }
    
}
