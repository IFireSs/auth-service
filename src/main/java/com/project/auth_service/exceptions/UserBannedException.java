package com.project.auth_service.exceptions;

public class UserBannedException extends RuntimeException {
    public UserBannedException() {
        super("User is banned");
    }
}
