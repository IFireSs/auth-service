package com.project.auth_service.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.config.KafkaEventProperties;
import com.project.auth_service.entity.AuditEvent;
import com.project.auth_service.entity.OutboxEvent;
import com.project.auth_service.enums.OutboxEventStatus;
import com.project.auth_service.repository.OutboxEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OutboxEventService {
    private final OutboxEventRepository outboxEventRepository;
    private final KafkaEventProperties kafkaEventProperties;
    private final ObjectMapper objectMapper;

    @Transactional
    public void enqueueAuditEvent(AuditEvent auditEvent) {
        if (!kafkaEventProperties.enabled()) {
            return;
        }

        Instant now = Instant.now();
        outboxEventRepository.save(OutboxEvent.builder()
                .id(UUID.randomUUID())
                .topic(kafkaEventProperties.topic())
                .eventKey(auditEvent.getId().toString())
                .eventType(auditEvent.getEventType().name())
                .payloadJson(toPayloadJson(auditEvent))
                .status(OutboxEventStatus.PENDING)
                .attempts(0)
                .createdAt(now)
                .nextAttemptAt(now)
                .build());
    }

    @Transactional
    public List<OutboxEvent> claimPublishable(Instant now) {
        List<OutboxEvent> events = outboxEventRepository.lockPublishable(
                now,
                kafkaEventProperties.maxAttempts(),
                kafkaEventProperties.batchSize()
        );
        Instant leaseExpiresAt = now.plusMillis(kafkaEventProperties.retryDelayMs());
        events.forEach(event -> event.markProcessing(leaseExpiresAt));
        return events;
    }

    @Transactional
    public void markPublished(OutboxEvent event, Instant publishedAt) {
        outboxEventRepository.findById(event.getId())
                .ifPresent(storedEvent -> storedEvent.markPublished(publishedAt));
    }

    @Transactional
    public void markFailed(OutboxEvent event, String error, Instant nextAttemptAt) {
        outboxEventRepository.findById(event.getId())
                .ifPresent(storedEvent -> storedEvent.markFailed(error, nextAttemptAt));
    }

    private String toPayloadJson(AuditEvent auditEvent) {
        try {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("id", auditEvent.getId());
            payload.put("eventType", auditEvent.getEventType());
            payload.put("occurredAt", auditEvent.getOccurredAt());
            payload.put("actorUserId", auditEvent.getActorUserId());
            payload.put("targetUserId", auditEvent.getTargetUserId());
            payload.put("username", auditEvent.getUsername());
            payload.put("sessionId", auditEvent.getSessionId());
            payload.put("ip", auditEvent.getIp());
            payload.put("userAgent", auditEvent.getUserAgent());
            payload.put("details", objectMapper.readTree(auditEvent.getDetailsJson()));
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{}";
        }
    }
}
