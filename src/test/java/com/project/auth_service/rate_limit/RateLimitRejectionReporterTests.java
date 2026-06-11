package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitAuditProperties;
import com.project.auth_service.service.AuditEventService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Clock;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class RateLimitRejectionReporterTests {

    @Test
    void countsEveryRejectionButLimitsAuditEventsPerKeyAndGlobally() {
        RateLimitAuditProperties properties = new RateLimitAuditProperties(
                2,
                Duration.ofMinutes(1),
                Duration.ofMinutes(5)
        );
        AuditEventService auditEventService = mock(AuditEventService.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        RateLimitRejectionReporter reporter = new RateLimitRejectionReporter(
                new RateLimitAuditEmissionLimiter(properties, Clock.systemUTC()),
                auditEventService,
                meterRegistry
        );
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");

        reporter.report(RateLimitService.Scope.LOGIN_IP, "203.0.113.1", request);
        reporter.report(RateLimitService.Scope.LOGIN_IP, "203.0.113.1", request);
        reporter.report(RateLimitService.Scope.LOGIN_IP, "203.0.113.2", request);
        reporter.report(RateLimitService.Scope.LOGIN_IP, "203.0.113.3", request);

        verify(auditEventService, times(2)).record(eq(com.project.auth_service.enums.AuditEventType.RATE_LIMIT_EXCEEDED), any());
        assertEquals(4.0, counter(meterRegistry, "auth.rate_limit.rejected"));
        assertEquals(2.0, counter(meterRegistry, "auth.rate_limit.audit.emitted"));
        assertEquals(2.0, counter(meterRegistry, "auth.rate_limit.audit.suppressed"));
    }

    private double counter(SimpleMeterRegistry meterRegistry, String name) {
        return meterRegistry.get(name)
                .tag("scope", RateLimitService.Scope.LOGIN_IP.name())
                .counter()
                .count();
    }
}
