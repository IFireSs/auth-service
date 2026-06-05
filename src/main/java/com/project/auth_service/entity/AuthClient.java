package com.project.auth_service.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "auth_clients")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthClient {
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "access_token_ttl_seconds", nullable = false)
    private long accessTokenTtlSeconds;

    @Column(name = "refresh_token_ttl_seconds", nullable = false)
    private long refreshTokenTtlSeconds;

    @Column(name = "token_audience", nullable = false)
    private String tokenAudience;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "allowed_origins", nullable = false, columnDefinition = "jsonb")
    private List<String> allowedOrigins;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public void update(String name,
                       long accessTokenTtlSeconds,
                       long refreshTokenTtlSeconds,
                       String tokenAudience,
                       List<String> allowedOrigins,
                       Instant updatedAt) {
        this.name = name;
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
        this.tokenAudience = tokenAudience;
        this.allowedOrigins = allowedOrigins;
        this.updatedAt = updatedAt;
    }

    public void enable(Instant updatedAt) {
        this.enabled = true;
        this.updatedAt = updatedAt;
    }

    public void disable(Instant updatedAt) {
        this.enabled = false;
        this.updatedAt = updatedAt;
    }
}
