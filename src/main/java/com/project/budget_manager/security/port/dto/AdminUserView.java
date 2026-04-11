package com.project.budget_manager.security.port.dto;

import com.project.budget_manager.security.enums.Role;

import java.util.List;

public record AdminUserView(
        Long id,
        String username,
        String email,
        List<Role> roles
) {
}
