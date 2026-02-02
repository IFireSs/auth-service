package com.project.budget_manager.persistence.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class UserRoleQueryRepository {
    private final JdbcTemplate jdbcTemplate;

    public List<String> findRolesByUserId(long userId) {
        return jdbcTemplate.queryForList(
                "select role from user_roles where user_id = ?",
                String.class,
                userId
        );
    }
}
