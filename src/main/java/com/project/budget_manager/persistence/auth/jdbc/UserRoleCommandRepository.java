package com.project.budget_manager.persistence.auth.jdbc;

import com.project.budget_manager.security.enums.Role;

@Deprecated
public interface UserRoleCommandRepository {
    void addRole(Long userId, Role role);
}
