package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.entity.User;
import com.project.budget_manager.repository.UserRepository;
import com.project.budget_manager.security.enums.Role;
import com.project.budget_manager.security.exceptions.EmailAlreadyExistsException;
import com.project.budget_manager.security.exceptions.UsernameAlreadyExistsException;
import com.project.budget_manager.security.port.AuthUser;
import com.project.budget_manager.security.port.AuthUserRegistrar;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
@Transactional
public class JpaAuthUserRegistrar implements AuthUserRegistrar {

    private final UserRepository userRepository;
    private final UserRoleCommandRepository userRoleCommandRepository;

    @Override
    public AuthUser register(String username, String email, String passwordHash){
        if(userRepository.existsByUsername(username)){
            throw new UsernameAlreadyExistsException();
        }
        if (userRepository.existsByEmail(email)){
            throw new EmailAlreadyExistsException();
        }
        User user = userRepository.save(User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordHash)
                .build());

        userRoleCommandRepository.addRole(user.getId(), Role.USER);
        return new AuthUser(user.getId(), user.getUsername(), user.getPasswordHash(), List.of(Role.USER));
    }
}
