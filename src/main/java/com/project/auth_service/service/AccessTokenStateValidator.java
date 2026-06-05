package com.project.auth_service.service;

import com.project.auth_service.config.AppSecurityProperties;
import com.project.auth_service.repository.RefreshTokenRepository;
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
    private final AuthClientService authClientService;

    @Override
    @Transactional(readOnly = true)
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (securityProperties.accessToken().validationMode() == AppSecurityProperties.ValidationMode.STATELESS) {
            return OAuth2TokenValidatorResult.success();
        }

        Long userId = JwtClaims.userId(token);
        String sessionId = JwtClaims.sessionId(token);
        String clientId = JwtClaims.clientId(token);
        if (userId == null || sessionId == null || sessionId.isBlank() || clientId == null || clientId.isBlank()) {
            return OAuth2TokenValidatorResult.failure(ACCESS_TOKEN_SESSION_INVALID);
        }
        if (!authClientService.existsActiveClient(clientId)) {
            return OAuth2TokenValidatorResult.failure(ACCESS_TOKEN_SESSION_INVALID);
        }

        boolean sessionActive = refreshTokenRepository.existsByUserIdAndClientIdAndSessionIdAndRevokedFalseAndExpiresAtAfter(
                userId,
                clientId,
                sessionId,
                Instant.now()
        );

        if (!sessionActive) {
            return OAuth2TokenValidatorResult.failure(ACCESS_TOKEN_SESSION_INVALID);
        }

        return OAuth2TokenValidatorResult.success();
    }
}
