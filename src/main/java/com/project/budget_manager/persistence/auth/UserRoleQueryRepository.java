package com.project.budget_manager.persistence.auth;

import com.project.budget_manager.security.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class UserRoleQueryRepository {
    // для тренировки jdbcTemplate, позже будет jpa
    private final JdbcTemplate jdbcTemplate;

    public List<Role> findRolesByUserId(long userId) {
        List<String> raw = jdbcTemplate.queryForList(
                "select role from user_roles where user_id = ?",
                String.class,
                userId
        );

        return raw.stream()
                .map(Role::fromAuthority)
                .toList();
    }
}
