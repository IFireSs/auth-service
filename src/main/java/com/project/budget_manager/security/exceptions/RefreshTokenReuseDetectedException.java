package com.project.budget_manager.security.exceptions;

public class RefreshTokenReuseDetectedException extends RuntimeException {
    public RefreshTokenReuseDetectedException() { super("Reuse detected, all sessions revoked"); }
}
