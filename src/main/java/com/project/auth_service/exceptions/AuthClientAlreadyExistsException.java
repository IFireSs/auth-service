package com.project.auth_service.exceptions;

public class AuthClientAlreadyExistsException extends RuntimeException {
    public AuthClientAlreadyExistsException() {
        super("Client application with this id already exists");
    }
}
