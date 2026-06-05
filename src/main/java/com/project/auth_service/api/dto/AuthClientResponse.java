package com.project.auth_service.api.dto;

import java.time.Instant;
import java.util.List;

public record AuthClientResponse(
        Long id,
        String clientId,
        String name,
        boolean enabled,
        long accessTokenTtlSeconds,
        long refreshTokenTtlSeconds,
        String tokenAudience,
        List<String> allowedOrigins,
        Instant createdAt,
        Instant updatedAt
) {
}
