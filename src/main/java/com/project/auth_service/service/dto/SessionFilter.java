package com.project.auth_service.service.dto;

import com.project.auth_service.enums.SessionStatus;

public record SessionFilter(
        SessionStatus status
) {
}
