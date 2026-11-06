package com.twomites.certificate_validator.validator;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

import com.twomites.certificate_validator.testdata.BadSslCertificateTestData;
import com.twomites.certificate_validator.testdata.CertificateTestData;
import com.twomites.certificate_validator.testdata.CertificateTestData.BadSslTestCase;

class CertificateExpiryValidatorTest {
    private CertificateExpiryValidator validator;

    @BeforeEach
    void setUp() {
        validator = new CertificateExpiryValidator();
    }

     /**
     * Provides BadSSL test scenarios.
     */
    static Stream<BadSslTestCase> badSslTestCases() {
        return CertificateTestData.getBadSslTestCases().stream();
  
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("badSslTestCases")
    void validateCertificateExpiry(BadSslTestCase testCase)
            throws Exception {

        X509Certificate certificate =
                BadSslCertificateTestData.getCertificateChain(testCase)[0];
                        

        boolean result = validator.isValid(certificate);

        assertEquals(
                testCase.expectedExpiryValid(),
                result,
                testCase.name()
        );
    }

}