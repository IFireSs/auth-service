package com.project.budget_manager.security.port;

import com.project.budget_manager.security.port.dto.AuthUser;

public interface IAuthUserRegistrar {
    AuthUser register(String username, String email, String passwordHash);
}
