package com.project.auth_service.service.dto;

import com.project.auth_service.enums.AuditEventType;

import java.time.Instant;
import java.util.UUID;

public record AuditEventFilter(
        AuditEventType eventType,
        UUID userId,
        UUID actorUserId,
        UUID targetUserId,
        String username,
        String sessionId,
        String ip,
        Instant from,
        Instant to
) {
}
