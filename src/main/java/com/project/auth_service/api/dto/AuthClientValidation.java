package com.project.auth_service.api.dto;

public final class AuthClientValidation {
    public static final int CLIENT_ID_MAX_LENGTH = 128;
    public static final int NAME_MAX_LENGTH = 128;
    public static final int TOKEN_AUDIENCE_MAX_LENGTH = 128;
    public static final int MAX_ALLOWED_ORIGINS = 50;
    public static final int ORIGIN_MAX_LENGTH = 256;
    public static final long ACCESS_TOKEN_TTL_MAX_SECONDS = 86_400;
    public static final long REFRESH_TOKEN_TTL_MAX_SECONDS = 7_776_000;

    private AuthClientValidation() {
    }
}
