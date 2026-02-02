package com.project.budget_manager.persistence.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class JdbcUserRoleCommandRepository implements UserRoleCommandRepository {
    private final JdbcTemplate jdbcTemplate;

    @Override
    public void addRole(Long userId, String role){
        jdbcTemplate.update(
                "insert into user_roles(user_id, role) values (?, ?)",
                userId, role
        );
    }
}
