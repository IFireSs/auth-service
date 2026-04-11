package com.project.budget_manager.security.enums;

import lombok.AllArgsConstructor;

import java.util.Arrays;

@AllArgsConstructor
public enum Role {
    USER,
    ADMIN,
    SUPER_ADMIN;

    public String authority() {
        return "ROLE_" + name();
    }
}
