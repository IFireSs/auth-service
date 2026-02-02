package com.project.budget_manager.security.port;

import java.util.Optional;

public interface AuthUserProvider {
    Optional<AuthUser> findByUsername(String username);
    Optional<AuthUser> findById(Long id);
}
