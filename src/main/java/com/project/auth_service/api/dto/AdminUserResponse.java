package com.project.auth_service.api.dto;

import com.project.auth_service.enums.Role;

import java.util.List;
import java.time.Instant;
import java.util.UUID;

public record AdminUserResponse(
        UUID id,
        String username,
        String email,
        Instant createdAt,
        boolean banProtected,
        UserBanResponse activeBan,
        List<Role> roles
) {
}
