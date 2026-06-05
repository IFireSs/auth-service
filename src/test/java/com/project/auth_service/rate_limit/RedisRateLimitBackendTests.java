package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
class RedisRateLimitBackendTests {
    @Container
    private static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);

    @Test
    void tryConsumeDoesNotPartiallyConsumeWhenOneBucketIsRejected() {
        LettuceConnectionFactory connectionFactory = connectionFactory();
        try {
            RedisRateLimitBackend backend = new RedisRateLimitBackend(properties(), new StringRedisTemplate(connectionFactory));
            RateLimitBackend.Request ipBucket = new RateLimitBackend.Request(
                    RateLimitService.Scope.LOGIN_IP,
                    "203.0.113.10",
                    new RateLimitProperties.Limit(2, Duration.ofMinutes(10))
            );
            RateLimitBackend.Request usernameIpBucket = new RateLimitBackend.Request(
                    RateLimitService.Scope.LOGIN_USERNAME_IP,
                    "alice:203.0.113.10",
                    new RateLimitProperties.Limit(1, Duration.ofMinutes(10))
            );

            RateLimitBackend.Result first = backend.tryConsume(List.of(ipBucket, usernameIpBucket));
            assertTrue(first.consumed());

            RateLimitBackend.Result rejected = backend.tryConsume(List.of(ipBucket, usernameIpBucket));
            assertFalse(rejected.consumed());
            assertEquals(RateLimitService.Scope.LOGIN_USERNAME_IP, rejected.rejectedScope());

            RateLimitBackend.Result ipOnly = backend.tryConsume(List.of(ipBucket));
            assertTrue(ipOnly.consumed());
        } finally {
            connectionFactory.destroy();
        }
    }

    private LettuceConnectionFactory connectionFactory() {
        RedisStandaloneConfiguration configuration = new RedisStandaloneConfiguration(
                REDIS.getHost(),
                REDIS.getMappedPort(6379)
        );
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();
        return connectionFactory;
    }

    private RateLimitProperties properties() {
        return new RateLimitProperties(
                new RateLimitProperties.Limit(5, Duration.ofMinutes(10)),
                new RateLimitProperties.Limit(10, Duration.ofMinutes(10)),
                new RateLimitProperties.Limit(30, Duration.ofMinutes(1)),
                new RateLimitProperties.Limit(60, Duration.ofMinutes(1)),
                RateLimitProperties.Backend.REDIS,
                "test:rate-limit:" + UUID.randomUUID(),
                List.of()
        );
    }
}
