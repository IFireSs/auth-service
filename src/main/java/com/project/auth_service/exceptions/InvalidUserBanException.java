package com.project.auth_service.exceptions;

public class InvalidUserBanException extends RuntimeException {
    public InvalidUserBanException(String message) {
        super(message);
    }
}
