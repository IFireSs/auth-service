package com.project.auth_service.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.events.kafka")
public record KafkaEventProperties(
        boolean enabled,
        @NotBlank String topic,
        @Min(1) int batchSize,
        @Min(1) long publisherFixedDelayMs,
        @Min(1) long retryDelayMs,
        @Min(1) long leaseDurationMs,
        @Min(1) long sendTimeoutMs,
        @Min(1) int maxAttempts
) {
    @AssertTrue(message = "Kafka outbox lease duration must exceed batch size multiplied by send timeout")
    public boolean isLeaseLongEnoughForBatch() {
        return batchSize > 0
                && sendTimeoutMs > 0
                && leaseDurationMs > 0
                && sendTimeoutMs <= Long.MAX_VALUE / batchSize
                && leaseDurationMs > batchSize * sendTimeoutMs;
    }
}
