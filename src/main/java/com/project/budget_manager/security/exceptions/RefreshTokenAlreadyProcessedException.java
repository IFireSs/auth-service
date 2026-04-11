package com.project.budget_manager.security.exceptions;

public class RefreshTokenAlreadyProcessedException extends RuntimeException {
    public RefreshTokenAlreadyProcessedException() {
        super("Refresh already processed by another request");
    }
}
