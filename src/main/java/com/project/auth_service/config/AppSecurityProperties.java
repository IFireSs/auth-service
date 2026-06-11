package com.project.auth_service.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.security")
public record AppSecurityProperties(
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull Cookies cookies,
        @Valid @NotNull Refresh refresh,
        @Valid @NotNull AccessToken accessToken
) {

    public record Jwt(
            @NotBlank String privateKey,
            @NotBlank String publicKey,
            @NotBlank String keyId
    ) {
    }

    public record Cookies(
            boolean secure,
            @NotBlank
            @Pattern(regexp = "Strict|Lax|None")
            String sameSite
    ) {
    }

    public record Refresh(
            boolean revokeDetect,
            @NotNull Duration ttl,
            @NotNull Duration reuseGrace,
            @NotBlank String replaySecret,
            @Valid @NotNull ClientBinding clientBinding,
            @Valid @NotNull Cleanup cleanup
    ) {
    }

    public record ClientBinding(
            boolean requireSessionId,
            boolean bindToUserAgent,
            boolean bindToIp
    ) {
    }

    public record Cleanup(
            boolean enabled,
            @NotNull Duration retention,
            @NotBlank String cron,
            @Min(1000) long replayPayloadCleanupFixedDelayMs
    ) {
    }

    public record AccessToken(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull @DurationMin(seconds = 1) Duration ttl,
            @NotNull ValidationMode validationMode
    ) {
    }

    public enum ValidationMode {
        STATELESS,
        STATEFUL
    }
}
