package com.project.auth_service.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@Validated
@ConfigurationProperties(prefix = "app.rate-limit")
public record RateLimitProperties(
        @Valid @NotNull Limit login,
        @Valid @NotNull Limit register,
        @Valid @NotNull Limit refresh,
        @Valid @NotNull Limit admin,
        @DefaultValue("IN_MEMORY") @NotNull Backend backend,
        @DefaultValue("auth-service:rate-limit") @NotBlank String redisKeyPrefix,
        @DefaultValue List<String> trustedProxies
) {
    public record Limit(
            @Min(1) long capacity,
            @NotNull Duration refillPeriod
    ) {
    }

    public enum Backend {
        IN_MEMORY,
        REDIS
    }
}
