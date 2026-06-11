package com.project.auth_service.service.dto;

import com.project.auth_service.enums.Role;

import java.util.List;
import java.util.UUID;

public record AuthUser(
        UUID id,
        String username,
        String passwordHash,
        List<Role> roles
) {
}
