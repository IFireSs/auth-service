package com.project.auth_service.enums;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum Role {
    USER,
    ADMIN,
    SUPER_ADMIN;

    public String authority() {
        return "ROLE_" + name();
    }
}
