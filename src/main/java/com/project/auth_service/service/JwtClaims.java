package com.project.auth_service.service;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public final class JwtClaims {
    public static final String USER_ID = "uid";
    public static final String SESSION_ID = "sid";
    public static final String CLIENT_ID = "client_id";
    public static final String ROLES = "roles";

    private JwtClaims() {
    }

    public static UUID userId(Jwt jwt) {
        if (jwt == null) {
            return null;
        }
        String claim = jwt.getClaimAsString(USER_ID);
        if (claim == null) {
            return null;
        }
        try {
            return UUID.fromString(claim);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String sessionId(Jwt jwt) {
        return jwt == null ? null : jwt.getClaimAsString(SESSION_ID);
    }

    public static String clientId(Jwt jwt) {
        return jwt == null ? null : jwt.getClaimAsString(CLIENT_ID);
    }
}
