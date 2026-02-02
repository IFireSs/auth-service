package com.project.budget_manager.persistence.auth;

public interface UserRoleCommandRepository {
    void addRole(Long userId, String role);
}
