package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.entity.User;
import com.project.budget_manager.repository.UserRepository;
import com.project.budget_manager.security.enums.Role;
import com.project.budget_manager.security.port.AuthUser;
import com.project.budget_manager.security.port.AuthUserProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JpaAuthUserProvider implements AuthUserProvider {
    private final UserRepository userRepository;
    private final UserRoleQueryRepository userRoleQueryRepository;

    @Override
    public Optional<AuthUser> findByUsername(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isEmpty()) {
            return Optional.empty();
        }
        User user = userOptional.get();
        Long userId = user.getId();
        List<Role> roles = userRoleQueryRepository.findRolesByUserId(userId);
        return Optional.of(new AuthUser(userId, user.getUsername(), user.getPasswordHash(), roles));
    }

    @Override
    public Optional<AuthUser> findById(Long userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isEmpty()) {
            return Optional.empty();
        }
        User user = userOptional.get();
        List<Role> roles = userRoleQueryRepository.findRolesByUserId(userId);
        return Optional.of(new AuthUser(userId, user.getUsername(), user.getPasswordHash(), roles));
    }
}
