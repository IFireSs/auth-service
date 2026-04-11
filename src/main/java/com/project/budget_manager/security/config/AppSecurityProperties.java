package com.project.budget_manager.security.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
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
            @NotBlank String secret
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
            @NotBlank String cron
    ) {
    }

    public record AccessToken(
            @NotBlank String issuer,
            @NotNull Duration ttl,
            @NotNull ValidationMode validationMode
    ) {
    }

    public enum ValidationMode {
        STATELESS,
        STATEFUL
    }
}
