package com.project.auth_service.service.dto;

import com.project.auth_service.enums.Role;

public record UserFilter(
        String query,
        Role role
) {
}
