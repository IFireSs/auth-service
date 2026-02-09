package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.security.enums.Role;

public interface UserRoleCommandRepository {
    void addRole(Long userId, Role role);
}
