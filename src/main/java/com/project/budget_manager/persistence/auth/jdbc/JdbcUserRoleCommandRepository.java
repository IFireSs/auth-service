package com.project.budget_manager.persistence.auth.jdbc;

import com.project.budget_manager.security.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Deprecated
@Repository
@RequiredArgsConstructor
public class JdbcUserRoleCommandRepository implements UserRoleCommandRepository {
    // для тренировки jdbcTemplate, позже будет jpa
    private final JdbcTemplate jdbcTemplate;

    @Override
    public void addRole(Long userId, Role role){
        jdbcTemplate.update(
                "insert into user_roles(user_id, role) values (?, ?)",
                userId, role.name()
        );
    }
}
