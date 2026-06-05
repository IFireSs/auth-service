package com.project.auth_service.exceptions;

public class AuthClientNotFoundException extends RuntimeException {
    public AuthClientNotFoundException() {
        super("Client application not found");
    }
}
