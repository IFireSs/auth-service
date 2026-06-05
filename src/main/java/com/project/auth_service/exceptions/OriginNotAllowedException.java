package com.project.auth_service.exceptions;

public class OriginNotAllowedException extends RuntimeException {
    public OriginNotAllowedException() {
        super("Origin is not allowed for this client application");
    }
}
