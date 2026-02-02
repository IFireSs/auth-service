package com.project.budget_manager.security.exceptions;

public class BadCredentialsException extends RuntimeException {
    public BadCredentialsException() {
        super("Invalid credentials");
    }
}
