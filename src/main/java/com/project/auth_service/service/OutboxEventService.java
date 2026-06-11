package com.project.auth_service.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.config.KafkaEventProperties;
import com.project.auth_service.entity.AuditEvent;
import com.project.auth_service.entity.OutboxEvent;
import com.project.auth_service.enums.OutboxEventStatus;
import com.project.auth_service.repository.OutboxEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
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
        int deadEvents = outboxEventRepository.markExhaustedAsDead(now, kafkaEventProperties.maxAttempts());
        if (deadEvents > 0) {
            log.error("Marked {} exhausted outbox event(s) as DEAD", deadEvents);
        }
        List<OutboxEvent> events = outboxEventRepository.lockPublishable(
                now,
                kafkaEventProperties.maxAttempts(),
                kafkaEventProperties.batchSize()
        );
        Instant leaseExpiresAt = now.plusMillis(kafkaEventProperties.leaseDurationMs());
        events.forEach(event -> event.markProcessing(UUID.randomUUID(), leaseExpiresAt, now));
        return events;
    }

    @Transactional
    public boolean markPublished(UUID eventId, UUID claimId, Instant publishedAt) {
        return outboxEventRepository.findByIdForUpdate(eventId)
                .filter(storedEvent -> storedEvent.isProcessingClaim(claimId))
                .map(storedEvent -> {
                    storedEvent.markPublished(publishedAt);
                    return true;
                })
                .orElse(false);
    }

    @Transactional
    public boolean markFailed(UUID eventId, UUID claimId, String error, Instant nextAttemptAt) {
        return outboxEventRepository.findByIdForUpdate(eventId)
                .filter(storedEvent -> storedEvent.isProcessingClaim(claimId))
                .map(storedEvent -> {
                    storedEvent.markFailed(error, nextAttemptAt, kafkaEventProperties.maxAttempts());
                    return true;
                })
                .orElse(false);
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
