package com.project.auth_service.service.dto;

import com.project.auth_service.enums.Role;

import java.util.List;

public record AuthUser(
        Long id,
        String username,
        String passwordHash,
        List<Role> roles
) {
}
