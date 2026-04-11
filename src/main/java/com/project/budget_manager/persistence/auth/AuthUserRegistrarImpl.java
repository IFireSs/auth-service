package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.entity.User;
import com.project.budget_manager.security.entity.UserRoleEntity;
import com.project.budget_manager.security.entity.UserRoleId;
import com.project.budget_manager.repository.UserRepository;
import com.project.budget_manager.security.enums.Role;
import com.project.budget_manager.security.exceptions.EmailAlreadyExistsException;
import com.project.budget_manager.security.exceptions.UsernameAlreadyExistsException;
import com.project.budget_manager.security.port.dto.AuthUser;
import com.project.budget_manager.security.port.IAuthUserRegistrar;
import com.project.budget_manager.security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
@Transactional
public class AuthUserRegistrarImpl implements IAuthUserRegistrar {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public AuthUser register(String username, String email, String passwordHash){
        if(userRepository.existsByUsername(username)){
            throw new UsernameAlreadyExistsException();
        }
        if (userRepository.existsByEmail(email)){
            throw new EmailAlreadyExistsException();
        }
        try {
            User user = userRepository.save(User.builder()
                    .username(username)
                    .email(email)
                    .passwordHash(passwordHash)
                    .build());

            userRoleRepository.save(new UserRoleEntity(new UserRoleId(user.getId(), Role.USER)));

            return new AuthUser(user.getId(), user.getUsername(), user.getPasswordHash(), List.of(Role.USER));
        } catch (DataIntegrityViolationException e) {
            if(userRepository.existsByUsername(username)){
                throw new UsernameAlreadyExistsException();
            }
            if (userRepository.existsByEmail(email)){
                throw new EmailAlreadyExistsException();
            }
            throw e;
        }

    }
}
