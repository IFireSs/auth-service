package com.project.auth_service.api.dto;

import com.project.auth_service.enums.Role;

import java.util.List;

public record AdminUserResponse(
        Long id,
        String username,
        String email,
        List<Role> roles
) {
}
