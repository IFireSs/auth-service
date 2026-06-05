package com.project.auth_service.repository;

import com.project.auth_service.entity.OutboxEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface OutboxEventRepository extends JpaRepository<OutboxEvent, UUID> {
    @Query(value = """
            SELECT *
            FROM {h-schema}outbox_events
            WHERE status IN ('PENDING', 'FAILED', 'PROCESSING')
              AND next_attempt_at <= :now
              AND attempts < :maxAttempts
            ORDER BY created_at ASC
            LIMIT :limit
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<OutboxEvent> lockPublishable(
            @Param("now") Instant now,
            @Param("maxAttempts") int maxAttempts,
            @Param("limit") int limit
    );
}
