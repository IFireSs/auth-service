package com.project.auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.bootstrap.super-admin")
public record SuperAdminBootstrapProperties(
        boolean enabled,
        boolean requireEmptyUserStore,
        String username,
        String email,
        String password
) {
}
