package com.project.budget_manager.security.cookie;

import com.project.budget_manager.security.config.AppSecurityProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SessionIdCookieFactory {

    private final boolean secure;
    private final String sameSite;
    private final Duration ttl;

    public SessionIdCookieFactory(AppSecurityProperties securityProperties) {
        this.secure = securityProperties.cookies().secure();
        this.sameSite = securityProperties.cookies().sameSite();
        this.ttl = securityProperties.refresh().ttl();
    }

    private static final String NAME = "session_id";
    private static final String PATH = "/api/v1/auth";

    public ResponseCookie buildSessionIdCookie(String sessionId){
        return ResponseCookie.from(NAME, sessionId)
                .path(PATH)
                .maxAge(ttl)
                .sameSite(sameSite)
                .httpOnly(true)
                .secure(secure)
                .build();
    }

    public ResponseCookie clearSessionIdCookie(){
        return ResponseCookie.from(NAME, "")
                .path(PATH)
                .maxAge(0)
                .sameSite(sameSite)
                .httpOnly(true)
                .secure(secure)
                .build();
    }
}
