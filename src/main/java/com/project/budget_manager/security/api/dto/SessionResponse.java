package com.project.budget_manager.security.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SessionResponse {
    private String deviceId;
    private String ip;
    private String userAgent;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant expiresAt;
}
