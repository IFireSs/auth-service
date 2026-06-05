package com.project.auth_service.exceptions;

public class InvalidAuthClientOriginException extends RuntimeException {
    public InvalidAuthClientOriginException(String origin) {
        super("Invalid auth client origin '%s'. Expected http(s)://host[:port] without path, query or fragment".formatted(origin));
    }
}
