package com.project.budget_manager.security.exceptions;

public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException() {
        super("conflict");
    }
}
