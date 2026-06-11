package com.project.auth_service.repository;

import com.project.auth_service.entity.OutboxEvent;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OutboxEventRepository extends JpaRepository<OutboxEvent, UUID> {
    @Query(value = """
            SELECT *
            FROM {h-schema}outbox_events
            WHERE attempts < :maxAttempts
              AND (
                    (status IN ('PENDING', 'FAILED') AND next_attempt_at <= :now)
                    OR (status = 'PROCESSING' AND lease_until <= :now)
                  )
            ORDER BY created_at ASC
            LIMIT :limit
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<OutboxEvent> lockPublishable(
            @Param("now") Instant now,
            @Param("maxAttempts") int maxAttempts,
            @Param("limit") int limit
    );

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            UPDATE {h-schema}outbox_events
            SET status = 'DEAD',
                claim_id = NULL,
                lease_until = NULL,
                last_error = COALESCE(last_error, 'Processing lease expired after maximum attempts')
            WHERE attempts >= :maxAttempts
              AND (
                    status IN ('PENDING', 'FAILED')
                    OR (status = 'PROCESSING' AND lease_until <= :now)
                  )
            """, nativeQuery = true)
    int markExhaustedAsDead(@Param("now") Instant now, @Param("maxAttempts") int maxAttempts);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select event from OutboxEvent event where event.id = :id")
    Optional<OutboxEvent> findByIdForUpdate(@Param("id") UUID id);
}
