package com.project.auth_service.entity;

import com.project.auth_service.enums.UserBanEndType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_bans")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserBan {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "reason", nullable = false, length = 500)
    private String reason;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @Column(name = "ended_at")
    private Instant endedAt;

    @Column(name = "ended_by")
    private UUID endedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "end_type")
    private UserBanEndType endType;

    public boolean isActiveAt(Instant instant) {
        return endedAt == null && (expiresAt == null || expiresAt.isAfter(instant));
    }

    public void end(Instant endedAt, UUID endedBy, UserBanEndType endType) {
        this.endedAt = endedAt;
        this.endedBy = endedBy;
        this.endType = endType;
    }
}
