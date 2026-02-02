package com.project.budget_manager.security.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.security.refresh.cleanup")
public record RefreshTokenCleanupProperties(
        boolean enabled,
        @NotNull Duration retention,
        @NotBlank String cron
) {}