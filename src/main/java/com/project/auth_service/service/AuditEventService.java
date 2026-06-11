package com.project.auth_service.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.api.dto.AuditEventResponse;
import com.project.auth_service.entity.AuditEvent;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.repository.AuditEventRepository;
import com.project.auth_service.service.dto.AuditEventFilter;
import com.project.auth_service.service.dto.OffsetBasedPageRequest;
import jakarta.persistence.criteria.Predicate;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditEventService {
    private static final TypeReference<Map<String, Object>> DETAILS_TYPE = new TypeReference<>() {
    };

    private final AuditEventRepository auditEventRepository;
    private final OutboxEventService outboxEventService;
    private final ObjectMapper objectMapper;

    @Transactional
    public void record(AuditEventType eventType, AuditEventCommand command) {
        persist(eventType, command);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordImmediately(AuditEventType eventType, AuditEventCommand command) {
        persist(eventType, command);
    }

    private void persist(AuditEventType eventType, AuditEventCommand command) {
        AuditEvent auditEvent = auditEventRepository.save(AuditEvent.builder()
                .id(UUID.randomUUID())
                .eventType(eventType)
                .occurredAt(Instant.now())
                .actorUserId(command.actorUserId())
                .targetUserId(command.targetUserId())
                .username(command.username())
                .sessionId(command.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .detailsJson(toJson(command.details()))
                .build());

        outboxEventService.enqueueAuditEvent(auditEvent);
    }

    @Transactional(readOnly = true)
    public List<AuditEventResponse> listEvents(AuditEventFilter filter, int limit, int offset) {
        Sort sort = Sort.by("occurredAt").descending().and(Sort.by("id").descending());

        return auditEventRepository.findAll(
                        specification(filter),
                        OffsetBasedPageRequest.capped(limit, offset, sort)
                )
                .stream()
                .map(this::toResponse)
                .toList();
    }

    private Specification<AuditEvent> specification(AuditEventFilter filter) {
        return (root, query, criteriaBuilder) -> {
            if (filter == null) {
                return criteriaBuilder.conjunction();
            }

            List<Predicate> predicates = new ArrayList<>();

            if (filter.eventType() != null) {
                predicates.add(criteriaBuilder.equal(root.get("eventType"), filter.eventType()));
            }
            if (filter.userId() != null) {
                predicates.add(criteriaBuilder.or(
                        criteriaBuilder.equal(root.get("actorUserId"), filter.userId()),
                        criteriaBuilder.equal(root.get("targetUserId"), filter.userId())
                ));
            }
            if (filter.actorUserId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("actorUserId"), filter.actorUserId()));
            }
            if (filter.targetUserId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("targetUserId"), filter.targetUserId()));
            }
            if (hasText(filter.username())) {
                predicates.add(criteriaBuilder.equal(root.get("username"), filter.username()));
            }
            if (hasText(filter.sessionId())) {
                predicates.add(criteriaBuilder.equal(root.get("sessionId"), filter.sessionId()));
            }
            if (hasText(filter.ip())) {
                predicates.add(criteriaBuilder.equal(root.get("ip"), filter.ip()));
            }
            if (filter.from() != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("occurredAt"), filter.from()));
            }
            if (filter.to() != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("occurredAt"), filter.to()));
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private AuditEventResponse toResponse(AuditEvent event) {
        return new AuditEventResponse(
                event.getId(),
                event.getEventType(),
                event.getOccurredAt(),
                event.getActorUserId(),
                event.getTargetUserId(),
                event.getUsername(),
                event.getSessionId(),
                event.getIp(),
                event.getUserAgent(),
                fromJson(event.getDetailsJson())
        );
    }

    private String toJson(Map<String, Object> details) {
        try {
            return objectMapper.writeValueAsString(details == null ? Map.of() : details);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Map<String, Object> fromJson(String detailsJson) {
        try {
            return objectMapper.readValue(detailsJson, DETAILS_TYPE);
        } catch (Exception e) {
            return Map.of();
        }
    }

    @Builder
    public record AuditEventCommand(
            UUID actorUserId,
            UUID targetUserId,
            String username,
            String sessionId,
            String ip,
            String userAgent,
            Map<String, Object> details
    ) {
    }
}
