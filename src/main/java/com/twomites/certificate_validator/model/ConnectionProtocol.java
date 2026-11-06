package com.twomites.certificate_validator.model;

/**
 * This defines the supported connection protocols and their default ports.
 * ConnectionProtocol
 */
public enum ConnectionProtocol {

    HTTPS(443),
    TLS(-1),
    SMTPS(465),
    SMTP_STARTTLS(587);

    private final int defaultPort;

    ConnectionProtocol(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public int getDefaultPort() {
        return defaultPort;
    }
}
