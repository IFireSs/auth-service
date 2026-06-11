package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app.rate-limit", name = "backend", havingValue = "in-memory", matchIfMissing = true)
public class InMemoryRateLimitBackend implements RateLimitBackend {
    private static final long CLEANUP_FIXED_DELAY_MS = 300_000;

    private final RateLimitProperties properties;
    private final Map<String, BucketState> buckets = new ConcurrentHashMap<>();

    @Override
    public synchronized Result tryConsume(List<Request> requests) {
        if (requests.isEmpty()) {
            return Result.allowed();
        }

        Instant now = Instant.now();
        for (Request request : requests) {
            BucketState state = bucketFor(request);
            state.refill(request.limit(), now);
            state.touch(now);
            if (!state.hasToken()) {
                return Result.rejected(request.scope(), state.retryAfter(request.limit()));
            }
        }

        for (Request request : requests) {
            bucketFor(request).consume();
        }
        return Result.allowed();
    }

    @Scheduled(fixedDelay = CLEANUP_FIXED_DELAY_MS)
    public void cleanupIdleBuckets() {
        Instant cutoff = Instant.now().minus(bucketRetention());
        buckets.entrySet().removeIf(entry -> entry.getValue().lastSeenAt().isBefore(cutoff));
    }

    private BucketState bucketFor(Request request) {
        return buckets.computeIfAbsent(storageKey(request), ignored -> BucketState.full(request.limit()));
    }

    private String storageKey(Request request) {
        return request.scope().keyPrefix() + ":" + request.key();
    }

    private Duration bucketRetention() {
        return max(properties.login().ip().refillPeriod(),
                properties.login().account().refillPeriod(),
                properties.login().accountIp().refillPeriod(),
                properties.register().refillPeriod(),
                properties.refresh().refillPeriod(),
                properties.admin().refillPeriod()
        ).multipliedBy(2);
    }

    private Duration max(Duration first, Duration... rest) {
        Duration max = first;
        for (Duration duration : rest) {
            if (duration.compareTo(max) > 0) {
                max = duration;
            }
        }
        return max;
    }

    private static class BucketState {
        private double tokens;
        private Instant refilledAt;
        private Instant lastSeenAt;

        private BucketState(double tokens, Instant refilledAt, Instant lastSeenAt) {
            this.tokens = tokens;
            this.refilledAt = refilledAt;
            this.lastSeenAt = lastSeenAt;
        }

        private static BucketState full(RateLimitProperties.Limit limit) {
            Instant now = Instant.now();
            return new BucketState(limit.capacity(), now, now);
        }

        private void refill(RateLimitProperties.Limit limit, Instant now) {
            long elapsedMillis = Math.max(0, Duration.between(refilledAt, now).toMillis());
            if (elapsedMillis == 0) {
                return;
            }

            double refillPeriodMillis = Math.max(1, limit.refillPeriod().toMillis());
            double refillTokens = elapsedMillis * ((double) limit.capacity() / refillPeriodMillis);
            this.tokens = Math.min(limit.capacity(), this.tokens + refillTokens);
            this.refilledAt = now;
        }

        private boolean hasToken() {
            return tokens >= 1.0;
        }

        private void consume() {
            this.tokens -= 1.0;
        }

        private Duration retryAfter(RateLimitProperties.Limit limit) {
            double missingTokens = Math.max(0, 1.0 - tokens);
            double refillPeriodMillis = Math.max(1, limit.refillPeriod().toMillis());
            long millis = (long) Math.ceil(missingTokens * refillPeriodMillis / limit.capacity());
            return Duration.ofMillis(Math.max(1, millis));
        }

        private Instant lastSeenAt() {
            return lastSeenAt;
        }

        private void touch(Instant now) {
            this.lastSeenAt = now;
        }
    }
}
