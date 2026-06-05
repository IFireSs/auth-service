package com.project.auth_service.api.dto;

public record ApiErrorResponse(
        String code,
        String message
) {
}
