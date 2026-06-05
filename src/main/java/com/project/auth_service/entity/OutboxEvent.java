package com.project.auth_service.entity;

import com.project.auth_service.enums.OutboxEventStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "outbox_events")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OutboxEvent {
    private static final int MAX_ERROR_LENGTH = 2000;

    @Id
    @Column(name = "id")
    private UUID id;

    @Column(name = "topic", nullable = false)
    private String topic;

    @Column(name = "event_key", nullable = false)
    private String eventKey;

    @Column(name = "event_type", nullable = false)
    private String eventType;

    @Column(name = "payload_json", nullable = false)
    private String payloadJson;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private OutboxEventStatus status;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "last_error")
    private String lastError;

    public void markProcessing(Instant nextAttemptAt) {
        this.status = OutboxEventStatus.PROCESSING;
        this.nextAttemptAt = nextAttemptAt;
    }

    public void markPublished(Instant publishedAt) {
        this.status = OutboxEventStatus.PUBLISHED;
        this.publishedAt = publishedAt;
        this.lastError = null;
    }

    public void markFailed(String error, Instant nextAttemptAt) {
        this.status = OutboxEventStatus.FAILED;
        this.attempts++;
        this.nextAttemptAt = nextAttemptAt;
        this.lastError = truncate(error);
    }

    private String truncate(String value) {
        if (value == null || value.length() <= MAX_ERROR_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_ERROR_LENGTH);
    }
}
