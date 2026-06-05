package com.project.auth_service.service;

import com.project.auth_service.api.dto.AuthClientCreateRequest;
import com.project.auth_service.api.dto.AuthClientResponse;
import com.project.auth_service.api.dto.AuthClientUpdateRequest;
import com.project.auth_service.config.AuthClientProperties;
import com.project.auth_service.entity.AuthClient;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.exceptions.AuthClientAlreadyExistsException;
import com.project.auth_service.exceptions.AuthClientNotFoundException;
import com.project.auth_service.exceptions.InvalidAuthClientOriginException;
import com.project.auth_service.exceptions.InvalidClientException;
import com.project.auth_service.exceptions.OriginNotAllowedException;
import com.project.auth_service.repository.AuthClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthClientService {
    private static final Duration ORIGIN_CACHE_TTL = Duration.ofSeconds(30);

    private final AuthClientRepository authClientRepository;
    private final AuthClientProperties properties;
    private final AuditEventService auditEventService;
    private volatile OriginCache originCache = new OriginCache(Set.of(), Instant.EPOCH);

    @Transactional(readOnly = true)
    public AuthClient resolveActiveClient(String requestedClientId) {
        String clientId = normalizeClientId(requestedClientId);
        return authClientRepository.findByClientIdAndEnabledTrue(clientId)
                .orElseThrow(InvalidClientException::new);
    }

    @Transactional(readOnly = true)
    public boolean existsActiveClient(String clientId) {
        return authClientRepository.existsByClientIdAndEnabledTrue(clientId);
    }

    @Transactional(readOnly = true)
    public boolean isOriginAllowedForAnyActiveClient(String origin) {
        String normalizedOrigin = normalizeRequestOrigin(origin);
        return normalizedOrigin != null && activeAllowedOrigins().contains(normalizedOrigin);
    }

    @Transactional(readOnly = true)
    public boolean isOriginAllowedForActiveClient(String clientId, String origin) {
        String normalizedOrigin = normalizeRequestOrigin(origin);
        if (normalizedOrigin == null) {
            return true;
        }
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        return authClientRepository.findByClientIdAndEnabledTrue(clientId.trim())
                .map(client -> isOriginAllowed(client, normalizedOrigin))
                .orElse(false);
    }

    public void validateOriginAllowed(AuthClient client, String origin) {
        String normalizedOrigin = normalizeRequestOrigin(origin);
        if (normalizedOrigin == null) {
            return;
        }
        if (!isOriginAllowed(client, normalizedOrigin)) {
            throw new OriginNotAllowedException();
        }
    }

    @Transactional(readOnly = true)
    public List<AuthClientResponse> listClients() {
        return authClientRepository.findAll(Sort.by("clientId").ascending()).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public AuthClientResponse getClient(String clientId) {
        return toResponse(findClient(clientId));
    }

    @Transactional
    public AuthClientResponse createClient(Long actorUserId, AuthClientCreateRequest request) {
        String clientId = request.clientId().trim();
        if (authClientRepository.existsByClientId(clientId)) {
            throw new AuthClientAlreadyExistsException();
        }

        Instant now = Instant.now();
        AuthClient client = AuthClient.builder()
                .clientId(clientId)
                .name(request.name().trim())
                .enabled(enabledOrDefault(request.enabled()))
                .accessTokenTtlSeconds(request.accessTokenTtlSeconds())
                .refreshTokenTtlSeconds(request.refreshTokenTtlSeconds())
                .tokenAudience(request.tokenAudience().trim())
                .allowedOrigins(normalizeOrigins(request.allowedOrigins()))
                .createdAt(now)
                .updatedAt(now)
                .build();

        try {
            AuthClient saved = authClientRepository.save(client);
            invalidateOriginCache();
            auditClientChange(AuditEventType.AUTH_CLIENT_CREATED, actorUserId, saved);
            return toResponse(saved);
        } catch (DataIntegrityViolationException e) {
            if (authClientRepository.existsByClientId(clientId)) {
                throw new AuthClientAlreadyExistsException();
            }
            throw e;
        }
    }

    @Transactional
    public AuthClientResponse updateClient(Long actorUserId, String clientId, AuthClientUpdateRequest request) {
        AuthClient client = findClient(clientId);
        client.update(
                request.name().trim(),
                request.accessTokenTtlSeconds(),
                request.refreshTokenTtlSeconds(),
                request.tokenAudience().trim(),
                normalizeOrigins(request.allowedOrigins()),
                Instant.now()
        );
        invalidateOriginCache();
        auditClientChange(AuditEventType.AUTH_CLIENT_UPDATED, actorUserId, client);
        return toResponse(client);
    }

    @Transactional
    public AuthClientResponse enableClient(Long actorUserId, String clientId) {
        AuthClient client = findClient(clientId);
        client.enable(Instant.now());
        invalidateOriginCache();
        auditClientChange(AuditEventType.AUTH_CLIENT_ENABLED, actorUserId, client);
        return toResponse(client);
    }

    @Transactional
    public AuthClientResponse disableClient(Long actorUserId, String clientId) {
        AuthClient client = findClient(clientId);
        client.disable(Instant.now());
        invalidateOriginCache();
        auditClientChange(AuditEventType.AUTH_CLIENT_DISABLED, actorUserId, client);
        return toResponse(client);
    }

    public Duration accessTokenTtl(AuthClient client) {
        return Duration.ofSeconds(client.getAccessTokenTtlSeconds());
    }

    public Duration refreshTokenTtl(AuthClient client) {
        return Duration.ofSeconds(client.getRefreshTokenTtlSeconds());
    }

    private String normalizeClientId(String requestedClientId) {
        if (requestedClientId == null || requestedClientId.isBlank()) {
            return properties.defaultClientId();
        }
        return requestedClientId.trim();
    }

    private AuthClient findClient(String clientId) {
        return authClientRepository.findByClientId(clientId.trim())
                .orElseThrow(AuthClientNotFoundException::new);
    }

    private boolean enabledOrDefault(Boolean enabled) {
        return enabled == null || enabled;
    }

    private AuthClientResponse toResponse(AuthClient client) {
        return new AuthClientResponse(
                client.getId(),
                client.getClientId(),
                client.getName(),
                client.isEnabled(),
                client.getAccessTokenTtlSeconds(),
                client.getRefreshTokenTtlSeconds(),
                client.getTokenAudience(),
                client.getAllowedOrigins(),
                client.getCreatedAt(),
                client.getUpdatedAt()
        );
    }

    private List<String> normalizeOrigins(List<String> allowedOrigins) {
        return allowedOrigins.stream()
                .map(this::normalizeConfiguredOrigin)
                .filter(origin -> origin != null)
                .distinct()
                .toList();
    }

    private Set<String> activeAllowedOrigins() {
        Instant now = Instant.now();
        OriginCache current = originCache;
        if (current.expiresAt().isAfter(now)) {
            return current.origins();
        }

        synchronized (this) {
            current = originCache;
            if (current.expiresAt().isAfter(now)) {
                return current.origins();
            }

            Set<String> origins = new HashSet<>();
            authClientRepository.findByEnabledTrue().forEach(client -> {
                if (client.getAllowedOrigins() != null) {
                    client.getAllowedOrigins().stream()
                            .map(this::normalizeRequestOrigin)
                            .filter(origin -> origin != null)
                            .forEach(origins::add);
                }
            });
            OriginCache refreshed = new OriginCache(Set.copyOf(origins), now.plus(ORIGIN_CACHE_TTL));
            originCache = refreshed;
            return refreshed.origins();
        }
    }

    private void invalidateOriginCache() {
        originCache = new OriginCache(Set.of(), Instant.EPOCH);
    }

    private String normalizeConfiguredOrigin(String origin) {
        String normalized = trimOrigin(origin);
        if (normalized == null) {
            return null;
        }
        return canonicalOrigin(normalized);
    }

    private String normalizeRequestOrigin(String origin) {
        String normalized = trimOrigin(origin);
        if (normalized == null) {
            return null;
        }
        try {
            return canonicalOrigin(normalized);
        } catch (InvalidAuthClientOriginException e) {
            return normalized;
        }
    }

    private String trimOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return null;
        }
        String normalized = origin.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isBlank() ? null : normalized;
    }

    private boolean isOriginAllowed(AuthClient client, String normalizedOrigin) {
        return client.getAllowedOrigins() != null
                && client.getAllowedOrigins().stream()
                .map(this::normalizeRequestOrigin)
                .anyMatch(normalizedOrigin::equals);
    }

    private String canonicalOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null
                    || host == null
                    || uri.getUserInfo() != null
                    || hasText(uri.getPath())
                    || uri.getQuery() != null
                    || uri.getFragment() != null) {
                throw new InvalidAuthClientOriginException(origin);
            }

            String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
            if (!"http".equals(normalizedScheme) && !"https".equals(normalizedScheme)) {
                throw new InvalidAuthClientOriginException(origin);
            }

            String normalizedHost = host.toLowerCase(Locale.ROOT);
            if (normalizedHost.contains(":") && !normalizedHost.startsWith("[")) {
                normalizedHost = "[" + normalizedHost + "]";
            }

            int port = uri.getPort();
            return port < 0
                    ? normalizedScheme + "://" + normalizedHost
                    : normalizedScheme + "://" + normalizedHost + ":" + port;
        } catch (IllegalArgumentException e) {
            throw new InvalidAuthClientOriginException(origin);
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private void auditClientChange(AuditEventType eventType, Long actorUserId, AuthClient client) {
        auditEventService.record(eventType, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .details(Map.of(
                        "clientId", client.getClientId(),
                        "enabled", client.isEnabled()
                ))
                .build());
    }

    private record OriginCache(Set<String> origins, Instant expiresAt) {
    }
}
