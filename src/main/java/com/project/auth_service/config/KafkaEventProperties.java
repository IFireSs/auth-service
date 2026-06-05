package com.project.auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.events.kafka")
public record KafkaEventProperties(
        boolean enabled,
        String topic,
        int batchSize,
        long publisherFixedDelayMs,
        long retryDelayMs,
        int maxAttempts
) {
}
