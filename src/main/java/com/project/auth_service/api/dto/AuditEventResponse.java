package com.project.auth_service.api.dto;

import com.project.auth_service.enums.AuditEventType;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record AuditEventResponse(
        UUID id,
        AuditEventType eventType,
        Instant occurredAt,
        UUID actorUserId,
        UUID targetUserId,
        String username,
        String sessionId,
        String ip,
        String userAgent,
        Map<String, Object> details
) {
}
