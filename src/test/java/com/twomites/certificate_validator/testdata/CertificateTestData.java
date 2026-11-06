package com.twomites.certificate_validator.testdata;

import java.util.List;

import com.twomites.certificate_validator.testdata.CertificateTestData.BadSslTestCase;

public class CertificateTestData {

    public record BadSslTestCase(
            String name,
            String url,
            String hostname,
            boolean expectedExpiryValid,
            boolean expectedSignatureValid,
            boolean expectedHostnameValid,
            boolean expectedPkixValid
    ) {}

  public static List<BadSslTestCase> getBadSslTestCases() {

        return List.of(

            new BadSslTestCase(
                "Valid public certificate",
                "https://sha256.badssl.com",
                "sha256.badssl.com",
                true, true, true, true
            ),

            new BadSslTestCase(
                "Expired certificate",
                "https://expired.badssl.com",
                "expired.badssl.com",
                false, true, true, false
            ),

            new BadSslTestCase(
                "Self-signed certificate",
                "https://self-signed.badssl.com",
                "self-signed.badssl.com",
                true, true, true, false
            ),

            new BadSslTestCase(
                "Wrong hostname",
                "https://wrong.host.badssl.com",
                "wrong.host.badssl.com",
                true, true, false, true
            ),

            new BadSslTestCase(
                "Untrusted root",
                "https://untrusted-root.badssl.com",
                "untrusted-root.badssl.com",
                true, true, true, false
            )

        );
    }
}