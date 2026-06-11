package com.project.auth_service.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.rate-limit.audit")
public record RateLimitAuditProperties(
        @Min(1) int globalCapacity,
        @NotNull @DurationMin(seconds = 1) Duration globalWindow,
        @NotNull @DurationMin(seconds = 1) Duration perKeyInterval
) {
}
