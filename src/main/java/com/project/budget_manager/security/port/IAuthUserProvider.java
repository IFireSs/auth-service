package com.project.budget_manager.security.port;

import com.project.budget_manager.security.port.dto.AuthUser;

import java.util.Optional;

public interface IAuthUserProvider {
    Optional<AuthUser> findByUsername(String username);
    Optional<AuthUser> findById(Long id);
}
