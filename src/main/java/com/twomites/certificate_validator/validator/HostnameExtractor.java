package com.twomites.certificate_validator.validator;

import java.net.URI;

import org.springframework.stereotype.Component;

@Component 
public class HostnameExtractor {
    
    public String extractHostname(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL cannot be null or blank");
        }

        try {
            URI uri = new URI(url);

            String hostname = uri.getHost();

            if (hostname == null || hostname.isBlank()) {
                throw new IllegalArgumentException("URL does not contain a valid hostname");
            }
            return hostname;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL format: " + e.getMessage(), e);
        }
         
    }
}
