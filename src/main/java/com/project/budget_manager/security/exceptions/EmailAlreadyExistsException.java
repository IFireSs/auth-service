package com.project.budget_manager.security.exceptions;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException() {
        super("conflict");
    }
}
