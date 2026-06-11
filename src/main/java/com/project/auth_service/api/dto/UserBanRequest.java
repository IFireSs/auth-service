package com.project.auth_service.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record UserBanRequest(
        Instant expiresAt,

        @NotBlank
        @Size(max = 500)
        String reason
) {
}
