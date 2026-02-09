package com.project.budget_manager.security.enums;

import lombok.AllArgsConstructor;

import java.util.Arrays;

@AllArgsConstructor
public enum Role {
    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    private final String authority;
    public String authority() {
        return authority;
    }
    public static Role fromAuthority(String authority) {
        return Arrays.stream(values())
                .filter(r -> r.authority.equals(authority))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown role authority: " + authority));
    }
}
