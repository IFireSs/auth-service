package com.project.auth_service.service.dto;

import com.project.auth_service.enums.AuditEventType;

import java.time.Instant;

public record AuditEventFilter(
        AuditEventType eventType,
        Long userId,
        Long actorUserId,
        Long targetUserId,
        String username,
        String sessionId,
        String ip,
        Instant from,
        Instant to
) {
}
