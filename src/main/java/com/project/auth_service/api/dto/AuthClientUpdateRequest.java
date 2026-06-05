package com.project.auth_service.api.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record AuthClientUpdateRequest(
        @NotBlank
        @Size(max = AuthClientValidation.NAME_MAX_LENGTH)
        String name,

        @Min(1)
        @Max(AuthClientValidation.ACCESS_TOKEN_TTL_MAX_SECONDS)
        long accessTokenTtlSeconds,

        @Min(1)
        @Max(AuthClientValidation.REFRESH_TOKEN_TTL_MAX_SECONDS)
        long refreshTokenTtlSeconds,

        @NotBlank
        @Size(max = AuthClientValidation.TOKEN_AUDIENCE_MAX_LENGTH)
        String tokenAudience,

        @NotNull
        @Size(max = AuthClientValidation.MAX_ALLOWED_ORIGINS)
        List<@NotBlank @Size(max = AuthClientValidation.ORIGIN_MAX_LENGTH) String> allowedOrigins
) {
}
