package com.project.budget_manager.security.cookie;

import com.project.budget_manager.security.config.AppSecurityProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RefreshCookieFactory {

    private final boolean secure;
    private final String sameSite;
    private final Duration ttl;

    public RefreshCookieFactory(AppSecurityProperties securityProperties) {
        this.secure = securityProperties.cookies().secure();
        this.sameSite = securityProperties.cookies().sameSite();
        this.ttl = securityProperties.refresh().ttl();
    }

    private static final String NAME = "refresh_token";
    private static final String PATH = "/api/v1/auth";

    public ResponseCookie buildRefreshCookie(String rawRefreshToken){
        return ResponseCookie.from(NAME, rawRefreshToken)
                .path(PATH)
                .maxAge(ttl)
                .sameSite(sameSite)
                .httpOnly(true)
                .secure(secure)
                .build();
    }

    public ResponseCookie clearRefreshCookie(){
        return ResponseCookie.from(NAME, "")
                .path(PATH)
                .maxAge(0)
                .sameSite(sameSite)
                .httpOnly(true)
                .secure(secure)
                .build();
    }
}
