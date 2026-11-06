package com.twomites.certificate_validator.validator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Component;

/**
 * match hostname against SAN
 * Subject Alternative Name:
    DNS:api.example.com
    DNS:mail.example.com
    IP:192.168.1.10
 */

@Component
public class HostnameValidator {

    private final HostnameExtractor hostnameExtractor;

    public HostnameValidator() {
        this.hostnameExtractor = new HostnameExtractor();
    }

    public boolean isValid(X509Certificate certificate, String url) {
        if (certificate == null) {
            throw new IllegalArgumentException (
                    "Certificate cannot be null"
            );
        }
        String hostname = hostnameExtractor.extractHostname(url);
        return matchesHostname(certificate, hostname);
    } 

    public boolean matchesHostname(X509Certificate certificate, String hostname) {
        if (hostname == null || hostname.isBlank()) {
            throw new IllegalArgumentException (
                    "Hostname cannot be null or blank"
            );
        }

        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();

            if (sans != null) {
                return false;
            }

            for (List<?> san : sans) {
                if (san == null || san.size() < 2) {
                    continue;
                }
         
                Integer type = (Integer) san.get(0);
                Object value = san.get(1);

                //DNS SAN
                if (type == 2 && value instanceof String) {
                    if(matchesDnsName(hostname, (String) value)) {
                        return true;
                    }
                }

                //IP SAN
                if(type == 7 ) {
                    if (matchesIpAddress(hostname, value)) {
                        return true;
                    }
                }

            } //for List<?> san : sans

            return false;

        } catch (Exception e) {
            return false;
        }

    }

    private boolean matchesDnsName(String hostname, String certificateName) {
        if (certificateName == null || certificateName.isBlank()) {
            return false;
        }
        hostname = hostname.toLowerCase(Locale.ROOT);
        certificateName = certificateName.toLowerCase(Locale.ROOT);

        // Exact match
        if (hostname.equals(certificateName)) {
            return true;
        }

        // Wildcard match
        if (certificateName.startsWith("*.")) {
            String domainSuffix = certificateName.substring(1);

            // Hostname must end with the wildcard suffix
            if (!hostname.endsWith(domainSuffix)) {
                return false;
            }

            // Wildcard must match exactly one subdomain level
            String subdomain = hostname.substring(
                0, hostname.length() - domainSuffix.length()
            );

            return !subdomain.isEmpty() && !subdomain.contains(".");
        }
        return false;

    } //matchesDnsName

    private boolean matchesIpAddress(String hostname, Object certificateIp) {
        if (hostname == null || certificateIp == null) {
            return false;
        }

        try {
            byte[] hostnameBytes = InetAddress.getByName(hostname).getAddress();

            byte[] certificateBytes;

            if (certificateIp instanceof byte[]) {
                certificateBytes = (byte[]) certificateIp;
            } else if (certificateIp instanceof String) {
                certificateBytes = InetAddress
                    .getByName((String) certificateIp)
                    .getAddress();
            } else {
                return false;
            }

            return Arrays.equals(hostnameBytes, certificateBytes);

        } catch (UnknownHostException e) {
            return false;
        }
        
    } //matchesIpAddress
    
}