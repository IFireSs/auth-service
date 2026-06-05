package com.project.auth_service.exceptions;

public class RefreshTokenAlreadyProcessedException extends RuntimeException {
    public RefreshTokenAlreadyProcessedException() {
        super("Refresh token was already processed by another request");
    }
}
