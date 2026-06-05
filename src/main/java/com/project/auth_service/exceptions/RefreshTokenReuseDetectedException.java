package com.project.auth_service.exceptions;

public class RefreshTokenReuseDetectedException extends RuntimeException {
    public RefreshTokenReuseDetectedException() { super("Refresh token reuse detected. All sessions have been revoked"); }
}
