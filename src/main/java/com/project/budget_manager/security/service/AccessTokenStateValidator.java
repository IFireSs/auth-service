package com.project.budget_manager.security.service;

import com.project.budget_manager.security.config.AppSecurityProperties;
import com.project.budget_manager.security.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class AccessTokenStateValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error ACCESS_TOKEN_SESSION_INVALID = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "Access token session is no longer active",
            null
    );

    private final AppSecurityProperties securityProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    @Transactional(readOnly = true)
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (securityProperties.accessToken().validationMode() == AppSecurityProperties.ValidationMode.STATELESS) {
            return OAuth2TokenValidatorResult.success();
        }

        Long userId = extractUserId(token);
        String sessionId = token.getClaimAsString("sid");
        if (userId == null || sessionId == null || sessionId.isBlank()) {
            return OAuth2TokenValidatorResult.failure(ACCESS_TOKEN_SESSION_INVALID);
        }

        boolean sessionActive = refreshTokenRepository.existsByUserIdAndSessionIdAndRevokedFalseAndExpiresAtAfter(
                userId,
                sessionId,
                Instant.now()
        );

        if (!sessionActive) {
            return OAuth2TokenValidatorResult.failure(ACCESS_TOKEN_SESSION_INVALID);
        }

        return OAuth2TokenValidatorResult.success();
    }

    private Long extractUserId(Jwt token) {
        Object claim = token.getClaim("uid");
        if (claim instanceof Number number) {
            return number.longValue();
        }
        return null;
    }
}
