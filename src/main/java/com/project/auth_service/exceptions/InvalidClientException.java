package com.project.auth_service.exceptions;

public class InvalidClientException extends RuntimeException {
    public InvalidClientException() {
        super("Client application is unknown or disabled");
    }
}
