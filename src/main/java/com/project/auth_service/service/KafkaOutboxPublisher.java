package com.project.auth_service.service;

import com.project.auth_service.config.KafkaEventProperties;
import com.project.auth_service.entity.OutboxEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.events.kafka.enabled", havingValue = "true")
public class KafkaOutboxPublisher {
    private final OutboxEventService outboxEventService;
    private final KafkaEventProperties kafkaEventProperties;
    private final KafkaTemplate<String, String> kafkaTemplate;

    @Scheduled(fixedDelayString = "${app.events.kafka.publisher-fixed-delay-ms:5000}")
    public void publishDueEvents() {
        Instant now = Instant.now();
        for (OutboxEvent event : outboxEventService.claimPublishable(now)) {
            publish(event);
        }
    }

    private void publish(OutboxEvent event) {
        try {
            kafkaTemplate.send(event.getTopic(), event.getEventKey(), event.getPayloadJson()).get(5, TimeUnit.SECONDS);
            outboxEventService.markPublished(event, Instant.now());
        } catch (Exception e) {
            outboxEventService.markFailed(event, e.getMessage(), Instant.now().plusMillis(kafkaEventProperties.retryDelayMs()));
            log.warn("Failed to publish outbox event {} to Kafka", event.getId(), e);
        }
    }
}
