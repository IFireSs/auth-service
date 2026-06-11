package com.project.auth_service.api.dto;

import java.time.Instant;
import java.util.UUID;

public record UserBanResponse(
        UUID id,
        Instant createdAt,
        Instant expiresAt,
        String reason,
        UUID createdBy
) {
}
