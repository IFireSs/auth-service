package com.project.auth_service.rate_limit;

import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.service.AuditEventService;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class RateLimitRejectionReporter {
    private static final String REJECTED_METRIC = "auth.rate_limit.rejected";
    private static final String AUDIT_EMITTED_METRIC = "auth.rate_limit.audit.emitted";
    private static final String AUDIT_SUPPRESSED_METRIC = "auth.rate_limit.audit.suppressed";
    private static final String AUDIT_FAILED_METRIC = "auth.rate_limit.audit.failed";

    private final RateLimitAuditEmissionLimiter auditEmissionLimiter;
    private final AuditEventService auditEventService;
    private final MeterRegistry meterRegistry;

    public void report(RateLimitService.Scope scope, String clientIp, HttpServletRequest request) {
        increment(REJECTED_METRIC, scope);
        if (!auditEmissionLimiter.tryAcquire(scope, clientIp)) {
            increment(AUDIT_SUPPRESSED_METRIC, scope);
            return;
        }

        try {
            auditEventService.record(AuditEventType.RATE_LIMIT_EXCEEDED, AuditEventService.AuditEventCommand.builder()
                    .ip(clientIp)
                    .userAgent(request.getHeader(HttpHeaders.USER_AGENT))
                    .details(Map.of(
                            "scope", scope.name(),
                            "path", request.getRequestURI()
                    ))
                    .build());
            increment(AUDIT_EMITTED_METRIC, scope);
        } catch (Exception ignored) {
            increment(AUDIT_FAILED_METRIC, scope);
        }
    }

    private void increment(String metricName, RateLimitService.Scope scope) {
        meterRegistry.counter(metricName, "scope", scope.name()).increment();
    }
}
