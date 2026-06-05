package com.project.auth_service.exceptions;

public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException() { super("Refresh token is invalid or has been revoked"); }
}
