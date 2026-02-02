package com.project.budget_manager.security.port;

public interface AuthUserRegistrar {
    AuthUser register(String username, String email, String passwordHash);
}
