package com.project.budget_manager.security.port;

import com.project.budget_manager.security.enums.Role;
import com.project.budget_manager.security.port.dto.AdminUserView;

import java.util.List;
import java.util.Set;

public interface IAdminPort {
    List<AdminUserView> listUsers(int limit, int offset);
    void grantRole(Long userId, Role role);
    void revokeRole(Long userId, Role role);
    Set<Role> getRolesByUserId(Long userId);
}
