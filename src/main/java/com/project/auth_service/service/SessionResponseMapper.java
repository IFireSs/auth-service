package com.project.auth_service.service;

import com.project.auth_service.api.dto.SessionResponse;
import com.project.auth_service.entity.RefreshToken;
import com.project.auth_service.enums.SessionStatus;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class SessionResponseMapper {

    public SessionResponse toResponse(RefreshToken refreshToken) {
        return baseBuilder(refreshToken).build();
    }

    public SessionResponse toResponse(RefreshToken refreshToken, Instant now) {
        return baseBuilder(refreshToken)
                .status(statusOf(refreshToken, now))
                .build();
    }

    public SessionStatus statusOf(RefreshToken refreshToken, Instant now) {
        if (refreshToken.getCompromisedAt() != null) {
            return SessionStatus.COMPROMISED;
        }
        if (refreshToken.isRevoked()) {
            return SessionStatus.REVOKED;
        }
        if (!refreshToken.getExpiresAt().isAfter(now)) {
            return SessionStatus.EXPIRED;
        }
        return SessionStatus.ACTIVE;
    }

    private SessionResponse.SessionResponseBuilder baseBuilder(RefreshToken refreshToken) {
        return SessionResponse.builder()
                .sessionId(refreshToken.getSessionId())
                .clientId(refreshToken.getClientId())
                .ip(refreshToken.getIp())
                .userAgent(refreshToken.getUserAgent())
                .createdAt(refreshToken.getCreatedAt())
                .lastUsedAt(refreshToken.getLastUsedAt())
                .expiresAt(refreshToken.getExpiresAt())
                .revoked(refreshToken.isRevoked())
                .revokedAt(refreshToken.getRevokedAt())
                .compromisedAt(refreshToken.getCompromisedAt())
                .compromisedReason(refreshToken.getCompromisedReason());
    }
}
