package com.project.budget_manager.security.port;

import java.util.List;

public record AuthUser(
        Long id,
        String username,
        String passwordHash,
        List<String> roles
) {}
