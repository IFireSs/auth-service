package com.project.auth_service.rate_limit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.config.RateLimitProperties;
import com.project.auth_service.service.AuditEventService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class RateLimitFilterTests {

    @Test
    void adminRateLimitUsesIpInsteadOfAuthorizationHeader() throws Exception {
        RateLimitFilter filter = filterWithLimits(5, 5, 5, 1);

        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        filter.doFilter(adminRequest("Bearer first-invalid-token"), firstResponse, new MockFilterChain());
        assertEquals(200, firstResponse.getStatus());

        MockHttpServletResponse secondResponse = new MockHttpServletResponse();
        filter.doFilter(adminRequest("Bearer second-invalid-token"), secondResponse, new MockFilterChain());
        assertEquals(429, secondResponse.getStatus());
    }

    @Test
    void loginBodyTooLargeIsRejectedBeforeBodyIsCached() throws Exception {
        RateLimitFilter filter = filterWithLimits(5, 5, 5, 5);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr("203.0.113.10");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent("x".repeat(8193).getBytes());

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(413, response.getStatus());
    }

    @Test
    void loginRateLimitUsesBothUsernameAndIp() throws Exception {
        RateLimitFilter filter = filterWithLimits(2, 5, 5, 5);

        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        filter.doFilter(loginRequest("alice"), firstResponse, new MockFilterChain());
        assertEquals(200, firstResponse.getStatus());

        MockHttpServletResponse secondResponse = new MockHttpServletResponse();
        filter.doFilter(loginRequest("bob"), secondResponse, new MockFilterChain());
        assertEquals(200, secondResponse.getStatus());

        MockHttpServletResponse thirdResponse = new MockHttpServletResponse();
        filter.doFilter(loginRequest("charlie"), thirdResponse, new MockFilterChain());
        assertEquals(429, thirdResponse.getStatus());
    }

    private RateLimitFilter filterWithLimits(long loginCapacity,
                                             long registerCapacity,
                                             long refreshCapacity,
                                             long adminCapacity) {
        RateLimitProperties properties = new RateLimitProperties(
                new RateLimitProperties.Limit(loginCapacity, Duration.ofMinutes(1)),
                new RateLimitProperties.Limit(registerCapacity, Duration.ofMinutes(1)),
                new RateLimitProperties.Limit(refreshCapacity, Duration.ofMinutes(1)),
                new RateLimitProperties.Limit(adminCapacity, Duration.ofMinutes(1)),
                RateLimitProperties.Backend.IN_MEMORY,
                "auth-service:rate-limit",
                List.of()
        );
        return new RateLimitFilter(
                new RateLimitService(properties, new InMemoryRateLimitBackend(properties)),
                new ClientIpResolver(properties),
                mock(AuditEventService.class),
                new ObjectMapper()
        );
    }

    private MockHttpServletRequest adminRequest(String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/admin/users");
        request.setRemoteAddr("203.0.113.10");
        request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
        return request;
    }

    private MockHttpServletRequest loginRequest(String username) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr("203.0.113.10");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(("{\"username\":\"" + username + "\",\"password\":\"password\"}").getBytes());
        return request;
    }
}
