package com.project.auth_service.exceptions;

public class ExpiredRefreshTokenException extends RuntimeException {
    public ExpiredRefreshTokenException() { super("Refresh token has expired. Please sign in again"); }
}
