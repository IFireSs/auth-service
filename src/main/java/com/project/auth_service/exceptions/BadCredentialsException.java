package com.project.auth_service.exceptions;

public class BadCredentialsException extends RuntimeException {
    public BadCredentialsException() {
        super("Invalid username or password");
    }
}
