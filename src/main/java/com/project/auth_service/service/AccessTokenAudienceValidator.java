package com.project.auth_service.service;

import com.project.auth_service.config.AppSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AccessTokenAudienceValidator implements OAuth2TokenValidator<Jwt> {
    private static final OAuth2Error INVALID_AUDIENCE = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "Access token is not intended for auth-service",
            null
    );

    private final AppSecurityProperties securityProperties;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        List<String> audiences = token.getAudience();
        return audiences != null && audiences.contains(securityProperties.accessToken().audience())
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
    }
}
