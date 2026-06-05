package com.project.auth_service.rate_limit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.api.dto.ApiErrorResponse;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.exceptions.RequestBodyTooLargeException;
import com.project.auth_service.service.AuditEventService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {
    private static final String UNKNOWN_USERNAME = "unknown";
    private static final int MAX_LOGIN_BODY_BYTES = 8 * 1024;

    private final RateLimitService rateLimitService;
    private final ClientIpResolver clientIpResolver;
    private final AuditEventService auditEventService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        RateLimitTarget target = targetFor(request);
        if (target == null) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpServletRequest requestForChain = request;
        RateLimitBackend.Result result;
        if (target.scope().isLogin()) {
            if (request.getContentLengthLong() > MAX_LOGIN_BODY_BYTES) {
                writeBodyTooLargeResponse(response);
                return;
            }

            CachedBodyHttpServletRequest cachedRequest;
            try {
                cachedRequest = new CachedBodyHttpServletRequest(request, MAX_LOGIN_BODY_BYTES);
            } catch (RequestBodyTooLargeException e) {
                writeBodyTooLargeResponse(response);
                return;
            }
            String ip = clientIpResolver.resolve(request);
            String username = normalizeUsername(extractUsername(cachedRequest));
            result = rateLimitService.tryConsumeLogin(username, ip);
            requestForChain = cachedRequest;
        } else {
            result = rateLimitService.tryConsume(target.scope(), target.key());
        }

        if (result.consumed()) {
            filterChain.doFilter(requestForChain, response);
            return;
        }

        recordRateLimitExceeded(result.rejectedScope(), request);
        writeRateLimitResponse(response, result.retryAfter());
    }

    private RateLimitTarget targetFor(HttpServletRequest request) {
        String method = request.getMethod();
        String path = request.getRequestURI();
        String ip = clientIpResolver.resolve(request);

        if (HttpMethod.POST.matches(method) && "/api/v1/auth/login".equals(path)) {
            return new RateLimitTarget(RateLimitService.Scope.LOGIN_USERNAME_IP, ip);
        }
        if (HttpMethod.POST.matches(method) && "/api/v1/auth/register".equals(path)) {
            return new RateLimitTarget(RateLimitService.Scope.REGISTER, ip);
        }
        if (HttpMethod.POST.matches(method) && "/api/v1/auth/refresh".equals(path)) {
            return new RateLimitTarget(RateLimitService.Scope.REFRESH, ip);
        }
        if (path.startsWith("/api/v1/admin/")) {
            return new RateLimitTarget(RateLimitService.Scope.ADMIN, ip);
        }
        return null;
    }

    private String extractUsername(CachedBodyHttpServletRequest request) {
        try {
            byte[] body = request.getCachedBody();
            if (body.length == 0) {
                return UNKNOWN_USERNAME;
            }
            JsonNode json = objectMapper.readTree(new String(body, StandardCharsets.UTF_8));
            JsonNode username = json.get("username");
            if (username == null || username.asText().isBlank()) {
                return UNKNOWN_USERNAME;
            }
            return username.asText();
        } catch (Exception e) {
            return UNKNOWN_USERNAME;
        }
    }

    private String normalizeUsername(String username) {
        return username.trim().toLowerCase(Locale.ROOT);
    }

    private void recordRateLimitExceeded(RateLimitService.Scope scope, HttpServletRequest request) {
        try {
            auditEventService.record(AuditEventType.RATE_LIMIT_EXCEEDED, AuditEventService.AuditEventCommand.builder()
                    .ip(clientIpResolver.resolve(request))
                    .userAgent(request.getHeader(HttpHeaders.USER_AGENT))
                    .details(Map.of(
                            "scope", scope.name(),
                            "path", request.getRequestURI()
                    ))
                    .build());
        } catch (Exception ignored) {
        }
    }

    private void writeRateLimitResponse(HttpServletResponse response, Duration retryAfter) throws IOException {
        long retryAfterMillis = Math.max(1, retryAfter.toMillis());
        long retryAfterSeconds = Math.max(1, (retryAfterMillis + 999) / 1000);
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        objectMapper.writeValue(response.getWriter(),
                new ApiErrorResponse("RATE_LIMIT_EXCEEDED", "Too many requests. Please try again later"));
    }

    private void writeBodyTooLargeResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(),
                new ApiErrorResponse("REQUEST_BODY_TOO_LARGE", "Request body is too large"));
    }

    private record RateLimitTarget(RateLimitService.Scope scope, String key) {
    }
}
