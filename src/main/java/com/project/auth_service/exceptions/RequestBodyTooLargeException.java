package com.project.auth_service.exceptions;

import java.io.IOException;

public class RequestBodyTooLargeException extends IOException {
    public RequestBodyTooLargeException(int maxBytes) {
        super("Request body exceeds " + maxBytes + " bytes");
    }
}
