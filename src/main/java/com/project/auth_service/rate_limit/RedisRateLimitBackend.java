package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "app.rate-limit", name = "backend", havingValue = "redis")
public class RedisRateLimitBackend implements RateLimitBackend {
    private static final DefaultRedisScript<List> CONSUME_SCRIPT = new DefaultRedisScript<>("""
            local now = tonumber(ARGV[1])
            local request_count = tonumber(ARGV[2])
            local rejected_index = 0
            local retry_after_millis = 0

            for i = 1, request_count do
              local arg_offset = 2 + ((i - 1) * 3)
              local capacity = tonumber(ARGV[arg_offset + 1])
              local refill_period_millis = tonumber(ARGV[arg_offset + 2])
              local key = KEYS[i]

              local bucket = redis.call('HMGET', key, 'tokens', 'updated_at')
              local tokens = tonumber(bucket[1])
              local updated_at = tonumber(bucket[2])

              if tokens == nil or updated_at == nil then
                tokens = capacity
                updated_at = now
              else
                local elapsed = math.max(0, now - updated_at)
                tokens = math.min(capacity, tokens + (elapsed * capacity / refill_period_millis))
              end

              if tokens < 1 and rejected_index == 0 then
                rejected_index = i
                retry_after_millis = math.ceil((1 - tokens) * refill_period_millis / capacity)
              end
            end

            if rejected_index ~= 0 then
              return {0, rejected_index, math.max(1, retry_after_millis)}
            end

            for i = 1, request_count do
              local arg_offset = 2 + ((i - 1) * 3)
              local capacity = tonumber(ARGV[arg_offset + 1])
              local refill_period_millis = tonumber(ARGV[arg_offset + 2])
              local ttl_millis = tonumber(ARGV[arg_offset + 3])
              local key = KEYS[i]

              local bucket = redis.call('HMGET', key, 'tokens', 'updated_at')
              local tokens = tonumber(bucket[1])
              local updated_at = tonumber(bucket[2])

              if tokens == nil or updated_at == nil then
                tokens = capacity
                updated_at = now
              else
                local elapsed = math.max(0, now - updated_at)
                tokens = math.min(capacity, tokens + (elapsed * capacity / refill_period_millis))
              end

              redis.call('HSET', key, 'tokens', tokens - 1, 'updated_at', now)
              redis.call('PEXPIRE', key, ttl_millis)
            end

            return {1, 0, 0}
            """, List.class);

    private final RateLimitProperties properties;
    private final StringRedisTemplate redisTemplate;


    @Override
    public Result tryConsume(List<Request> requests) {
        if (requests.isEmpty()) {
            return Result.allowed();
        }

        List<String> keys = requests.stream()
                .map(this::storageKey)
                .toList();
        List<String> args = new ArrayList<>();
        args.add(Long.toString(Instant.now().toEpochMilli()));
        args.add(Integer.toString(requests.size()));
        for (Request request : requests) {
            RateLimitProperties.Limit limit = request.limit();
            args.add(Long.toString(limit.capacity()));
            args.add(Long.toString(Math.max(1, limit.refillPeriod().toMillis())));
            args.add(Long.toString(ttlMillis(limit)));
        }

        List<?> scriptResult = redisTemplate.execute(CONSUME_SCRIPT, keys, args.toArray());
        if (scriptResult == null || scriptResult.isEmpty() || asLong(scriptResult.getFirst()) == 1) {
            return Result.allowed();
        }

        int rejectedIndex = Math.toIntExact(asLong(scriptResult.get(1)));
        Duration retryAfter = Duration.ofMillis(Math.max(1, asLong(scriptResult.get(2))));
        RateLimitService.Scope rejectedScope = requests.get(rejectedIndex - 1).scope();
        return Result.rejected(rejectedScope, retryAfter);
    }

    private String storageKey(Request request) {
        return properties.redisKeyPrefix() + ":" + request.scope().keyPrefix() + ":" + request.key();
    }

    private long ttlMillis(RateLimitProperties.Limit limit) {
        return Math.max(1_000, limit.refillPeriod().multipliedBy(2).toMillis());
    }

    private long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }
}
