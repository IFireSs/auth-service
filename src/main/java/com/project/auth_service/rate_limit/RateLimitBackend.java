package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;

import java.time.Duration;
import java.util.List;

public interface RateLimitBackend {
    Result tryConsume(List<Request> requests);

    record Request(
            RateLimitService.Scope scope,
            String key,
            RateLimitProperties.Limit limit
    ) {
    }

    record Result(
            boolean consumed,
            RateLimitService.Scope rejectedScope,
            Duration retryAfter
    ) {
        public static Result allowed() {
            return new Result(true, null, Duration.ZERO);
        }

        public static Result rejected(RateLimitService.Scope rejectedScope, Duration retryAfter) {
            Duration normalizedRetryAfter = retryAfter == null || retryAfter.isNegative()
                    ? Duration.ZERO
                    : retryAfter;
            return new Result(false, rejectedScope, normalizedRetryAfter);
        }
    }
}
