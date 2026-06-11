package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitAuditProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

@Component
public class RateLimitAuditEmissionLimiter {
    private final RateLimitAuditProperties properties;
    private final Clock clock;
    private final Map<String, Instant> nextAllowedByKey = new HashMap<>();
    private final Deque<Instant> globalEmissions = new ArrayDeque<>();

    private Instant nextExpiredKeyCleanupAt;

    public RateLimitAuditEmissionLimiter(RateLimitAuditProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
        this.nextExpiredKeyCleanupAt = clock.instant().plus(properties.globalWindow());
    }

    public synchronized boolean tryAcquire(RateLimitService.Scope scope, String clientIp) {
        Instant now = clock.instant();
        evictExpiredGlobalEmissions(now);
        cleanupExpiredKeysIfRequired(now);

        String key = scope.name() + ":" + normalizeClientIp(clientIp);
        Instant nextAllowed = nextAllowedByKey.get(key);
        if (nextAllowed != null && nextAllowed.isAfter(now)) {
            return false;
        }
        if (globalEmissions.size() >= properties.globalCapacity()) {
            return false;
        }

        globalEmissions.addLast(now);
        nextAllowedByKey.put(key, now.plus(properties.perKeyInterval()));
        return true;
    }

    private void evictExpiredGlobalEmissions(Instant now) {
        Instant cutoff = now.minus(properties.globalWindow());
        while (!globalEmissions.isEmpty() && !globalEmissions.getFirst().isAfter(cutoff)) {
            globalEmissions.removeFirst();
        }
    }

    private void cleanupExpiredKeysIfRequired(Instant now) {
        if (!now.isBefore(nextExpiredKeyCleanupAt)) {
            nextAllowedByKey.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
            nextExpiredKeyCleanupAt = now.plus(properties.globalWindow());
        }
    }

    private String normalizeClientIp(String clientIp) {
        return clientIp == null || clientIp.isBlank() ? "unknown" : clientIp;
    }
}
