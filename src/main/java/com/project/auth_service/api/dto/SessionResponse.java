package com.project.auth_service.api.dto;

import lombok.Builder;
import lombok.Data;

import com.project.auth_service.enums.SessionStatus;

import java.time.Instant;

@Data
@Builder
public class SessionResponse {
    private String sessionId;
    private String clientId;
    private String ip;
    private String userAgent;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant expiresAt;
    private boolean revoked;
    private Instant revokedAt;
    private Instant compromisedAt;
    private String compromisedReason;
    private SessionStatus status;
}
