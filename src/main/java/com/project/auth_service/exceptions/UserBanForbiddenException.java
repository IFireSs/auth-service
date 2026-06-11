package com.project.auth_service.exceptions;

public class UserBanForbiddenException extends RuntimeException {
    public UserBanForbiddenException(String message) {
        super(message);
    }
}
