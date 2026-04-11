package com.project.budget_manager.security.port.dto;

import com.project.budget_manager.security.enums.Role;

import java.util.List;

public record AuthUser(
        Long id,
        String username,
        String passwordHash,
        List<Role> roles
) {}
