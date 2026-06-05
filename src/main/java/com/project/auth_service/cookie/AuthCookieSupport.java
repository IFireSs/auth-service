package com.project.auth_service.cookie;

import com.project.auth_service.config.AppSecurityProperties;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

abstract class AuthCookieSupport {
    private static final String PATH = "/api/v1/auth";

    private final boolean secure;
    private final String sameSite;
    private final Duration ttl;

    protected AuthCookieSupport(AppSecurityProperties securityProperties) {
        this.secure = securityProperties.cookies().secure();
        this.sameSite = securityProperties.cookies().sameSite();
        this.ttl = securityProperties.refresh().ttl();
    }

    protected ResponseCookie buildCookie(String name, String value) {
        return cookie(name, value)
                .maxAge(ttl)
                .build();
    }

    protected ResponseCookie clearCookie(String name) {
        return cookie(name, "")
                .maxAge(0)
                .build();
    }

    private ResponseCookie.ResponseCookieBuilder cookie(String name, String value) {
        return ResponseCookie.from(name, value)
                .path(PATH)
                .sameSite(sameSite)
                .httpOnly(true)
                .secure(secure);
    }
}
