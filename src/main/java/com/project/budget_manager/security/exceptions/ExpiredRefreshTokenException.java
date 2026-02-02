package com.project.budget_manager.security.exceptions;

public class ExpiredRefreshTokenException extends RuntimeException {
    public ExpiredRefreshTokenException() { super("Refresh token expired"); }
}
