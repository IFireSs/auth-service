package com.project.auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.auth-clients")
public record AuthClientProperties(
        String defaultClientId
) {
}
