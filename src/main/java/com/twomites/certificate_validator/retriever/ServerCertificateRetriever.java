package com.twomites.certificate_validator.retriever;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.stereotype.Component;

import com.twomites.certificate_validator.model.ConnectionProtocol;

@Component
public class ServerCertificateRetriever {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 10_000;

    private static final String SMTP_EHLO_DOMAIN =
            "certificate-validator.local";

    /**
     * Retrieves the certificate chain presented by a remote server.
     *
     * This method deliberately does not validate certificate trust or hostname.
     * Those checks are performed separately by the certificate validators.
     *
     * @param host remote server hostname or IP address
     * @param port remote server port; null uses the protocol default
     * @param protocol connection protocol
     * @return certificates presented by the server, leaf certificate first
     */
    public X509Certificate[] retrieve(
            String host,
            Integer port,
            ConnectionProtocol protocol)
            throws IOException, GeneralSecurityException {

        validateArguments(host, protocol);

        /**
         * https, port omitted -> default to 443
         * smpt_startls, port omitted -> default to 587
         * tls, port omitted -> throw exception because generic TLS has no default port
         * tls, port specified -> use specified port
         * https, port specified -> use specified port
         */

        if (port == null && protocol.getDefaultPort() == -1) {
             throw new IllegalArgumentException(
            "Port must be specified for generic TLS connections.");
}

        int targetPort = port != null
                ? port
                : protocol.getDefaultPort();

        if (targetPort < 1 || targetPort > 65535) {
            throw new IllegalArgumentException(
                    "Port must be between 1 and 65535.");
        }

        SSLContext sslContext = createInspectionSslContext();

        return switch (protocol) {
            case HTTPS, TLS, SMTPS ->
                    retrieveDirectTls(host, targetPort, sslContext);

            case SMTP_STARTTLS ->
                    retrieveSmtpStartTls(host, targetPort, sslContext);
        };
    }

    private X509Certificate[] retrieveDirectTls(
            String host,
            int port,
            SSLContext sslContext)
            throws IOException {

        try (Socket socket = new Socket()) {

            InetSocketAddress remoteAddress = new InetSocketAddress(host, port);

            System.out.println("Java resolved " + host + " to " 
                    + remoteAddress.getAddress().getHostAddress()
                    + ":" + remoteAddress.getPort());
          
            socket.connect(remoteAddress, CONNECT_TIMEOUT_MS);    
            // socket.connect(
            //         new InetSocketAddress(host, port),
            //         CONNECT_TIMEOUT_MS);

            socket.setSoTimeout(READ_TIMEOUT_MS);

            SSLSocketFactory factory = sslContext.getSocketFactory();

            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                    socket, host, port, true)) {

                configureSslSocket(sslSocket, host);

                sslSocket.startHandshake();

                return getPeerCertificates(sslSocket);
            }
        }
    }

    private X509Certificate[] retrieveSmtpStartTls(
            String host,
            int port,
            SSLContext sslContext)
            throws IOException {

        try (Socket socket = new Socket()) {

            socket.connect(
                    new InetSocketAddress(host, port),
                    CONNECT_TIMEOUT_MS);

            socket.setSoTimeout(READ_TIMEOUT_MS);

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            // SMTP server greeting
            expectSmtpResponse(input, 220);

            // Identify ourselves to the SMTP server.
            sendSmtpCommand(output, "EHLO " + SMTP_EHLO_DOMAIN);
            expectSmtpResponse(input, 250);

            // Request an upgrade to TLS.
            sendSmtpCommand(output, "STARTTLS");
            expectSmtpResponse(input, 220);

            // Upgrade the existing SMTP connection to TLS.
            SSLSocketFactory factory = sslContext.getSocketFactory();

            try (SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                    socket, host, port, true)) {

                configureSslSocket(sslSocket, host);

                sslSocket.startHandshake();

                return getPeerCertificates(sslSocket);
            }
        }
    }

    private void configureSslSocket(
            SSLSocket sslSocket,
            String host) {

        sslSocket.setUseClientMode(true);

        SSLParameters sslParameters = sslSocket.getSSLParameters();

        // Hostname validation is performed separately by HostnameValidator.
        sslParameters.setEndpointIdentificationAlgorithm(null);

        // SNI is used for DNS hostnames, not IP addresses.
        if (!isIpAddress(host)) {
            sslParameters.setServerNames(
                    List.of(new SNIHostName(host)));
        }

        sslSocket.setSSLParameters(sslParameters);
        try {
            sslSocket.setSoTimeout(READ_TIMEOUT_MS);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    private X509Certificate[] getPeerCertificates(
            SSLSocket sslSocket)
            throws IOException {

        Certificate[] peerCertificates =
                sslSocket.getSession().getPeerCertificates();

        X509Certificate[] result =
                new X509Certificate[peerCertificates.length];

        for (int i = 0; i < peerCertificates.length; i++) {

            if (!(peerCertificates[i] instanceof X509Certificate)) {
                throw new IOException(
                        "Server presented a non-X.509 certificate.");
            }

            result[i] = (X509Certificate) peerCertificates[i];
        }

        return result;
    }

    /**
     * Creates an SSL context that accepts certificates for inspection only.
     * Never use this context for normal application communication.
     */
    private SSLContext createInspectionSslContext()
            throws GeneralSecurityException {

        X509TrustManager inspectionTrustManager =
                new X509TrustManager() {

                    @Override
                    public void checkClientTrusted(
                            X509Certificate[] chain,
                            String authType) {
                        // Not used by this client.
                    }

                    @Override
                    public void checkServerTrusted(
                            X509Certificate[] chain,
                            String authType) {
                        // Intentionally accepts certificates for inspection.
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                };

        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(
                null,
                new TrustManager[] { inspectionTrustManager },
                new SecureRandom());

        return sslContext;
    }

    private void sendSmtpCommand(
            OutputStream output,
            String command)
            throws IOException {

        output.write((command + "\r\n").getBytes(
                java.nio.charset.StandardCharsets.US_ASCII));

        output.flush();
    }

    /**
     * Reads an SMTP response, including multiline responses.
     *
     * Example:
     * 250-mail.example.com
     * 250-STARTTLS
     * 250 OK
     */
    private void expectSmtpResponse(
            InputStream input,
            int expectedCode)
            throws IOException {

        String line;
        int responseCode = -1;
        boolean responseComplete = false;

        do {
            line = readSmtpLine(input);

            if (line.length() < 3
                    || !line.substring(0, 3).matches("\\d{3}")) {
                throw new IOException(
                        "Invalid SMTP response: " + line);
            }

            int currentCode = Integer.parseInt(
                    line.substring(0, 3));

            if (responseCode == -1) {
                responseCode = currentCode;
            } else if (currentCode != responseCode) {
                throw new IOException(
                        "Inconsistent SMTP multiline response: " + line);
            }

            responseComplete =
                    line.length() == 3 || line.charAt(3) == ' ';

        } while (!responseComplete);

        if (responseCode != expectedCode) {
            throw new IOException(
                    "Expected SMTP response " + expectedCode
                    + " but received " + responseCode);
        }
    }

    /**
     * Reads one SMTP line without buffering beyond its line ending.
     */
    private String readSmtpLine(InputStream input)
            throws IOException {

        StringBuilder line = new StringBuilder();

        int value;

        while ((value = input.read()) != -1) {

            if (value == '\n') {
                break;
            }

            if (value != '\r') {
                line.append((char) value);
            }

            if (line.length() > 2048) {
                throw new IOException(
                        "SMTP response line is too long.");
            }
        }

        if (value == -1) {
            throw new IOException(
                    "SMTP server closed the connection unexpectedly.");
        }

        return line.toString();
    }

    private boolean isIpAddress(String host) {
        return host.contains(":")
                || host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private void validateArguments(
            String host,
            ConnectionProtocol protocol) {

        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException(
                    "Host cannot be null or blank.");
        }

        if (protocol == null) {
            throw new IllegalArgumentException(
                    "Protocol cannot be null.");
        }
    }
}
