package com.twomites.certificate_validator.testdata;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.twomites.certificate_validator.testdata.CertificateTestData.BadSslTestCase;  



public class BadSslCertificateTestData {

    /**
     * Retrieves the certificate chain presented by a BadSSL server.
     *
     * This uses a test-only TrustManager that accepts all certificates
     * so that intentionally invalid certificates can be inspected.
     *
     * IMPORTANT:
     * This must never be used in production.
     */
    public static X509Certificate[] getCertificateChain(
            BadSslTestCase testCase) throws Exception {

        if (testCase == null) {
            throw new IllegalArgumentException(
                    "BadSSL test case cannot be null"
            );
        }

        String hostname = testCase.hostname();

        int port = 443;

        TrustManager[] trustManagers = {
            new X509TrustManager() {

                private X509Certificate[] capturedChain;

                @Override
                public void checkClientTrusted(
                        X509Certificate[] chain,
                        String authType) {
                }

                @Override
                public void checkServerTrusted(
                        X509Certificate[] chain,
                        String authType) {

                    capturedChain = chain.clone();
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(
                null,
                trustManagers,
                new java.security.SecureRandom()
        );

        try (Socket socket = new Socket()) {

            socket.connect(
                    new InetSocketAddress(hostname, port),
                    10000
            );

            try (SSLSocket sslSocket = (SSLSocket)
                    sslContext.getSocketFactory()
                            .createSocket(socket, hostname, port, true)) {

                sslSocket.setSoTimeout(10000);

                sslSocket.startHandshake();

                return Arrays.copyOf(
                        sslSocket.getSession().getPeerCertificates(),
                        sslSocket.getSession().getPeerCertificates().length,
                        X509Certificate[].class
                );
            }  //try-with-resources for SSLSocket
        }  //try-with-resources for Socket
     } //getCertificateChain
}
