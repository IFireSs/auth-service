package com.project.auth_service.enums;

public enum OutboxEventStatus {
    PENDING,
    PROCESSING,
    FAILED,
    DEAD,
    PUBLISHED
}
