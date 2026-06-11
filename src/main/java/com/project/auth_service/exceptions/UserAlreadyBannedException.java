package com.project.auth_service.exceptions;

public class UserAlreadyBannedException extends RuntimeException {
    public UserAlreadyBannedException() {
        super("User already has an active ban");
    }
}
