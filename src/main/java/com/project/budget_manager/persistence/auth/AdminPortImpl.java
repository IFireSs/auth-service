package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.security.entity.UserRoleEntity;
import com.project.budget_manager.security.entity.UserRoleId;
import com.project.budget_manager.repository.UserRepository;
import com.project.budget_manager.security.enums.Role;
import com.project.budget_manager.security.exceptions.UserNotFoundException;
import com.project.budget_manager.security.port.IAdminPort;
import com.project.budget_manager.security.port.dto.AdminUserView;
import com.project.budget_manager.security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Transactional
public class AdminPortImpl implements IAdminPort {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public List<AdminUserView> listUsers(int limit, int offset) {
        return userRepository.findAll().stream().limit(limit).skip(offset)
                .map(user -> new AdminUserView(user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        userRoleRepository.findRolesByUserId(user.getId())))
                .toList();
    }

    @Override
    public void grantRole(Long userId, Role role) {
        if (!userRepository.existsById(userId)) {
            throw new UserNotFoundException();
        }
        userRoleRepository.save(new UserRoleEntity(new UserRoleId(userId, role)));
    }

    @Override
    public void revokeRole(Long userId, Role role) {
        if (!userRepository.existsById(userId)) {
            throw new UserNotFoundException();
        }
        userRoleRepository.deleteById(new UserRoleId(userId, role));
    }

    @Override
    public Set<Role> getRolesByUserId(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new UserNotFoundException();
        }
        return new HashSet<>(userRoleRepository.findRolesByUserId(userId));
    }
}
