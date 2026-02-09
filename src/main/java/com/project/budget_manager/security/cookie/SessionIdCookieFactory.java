package com.project.budget_manager.security.cookie;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SessionIdCookieFactory {

    private final boolean secure;
    private final String sameSite;

    public SessionIdCookieFactory(@Value("${app.security.cookies.secure:true}") boolean secure
            , @Value("${app.security.cookies.sameSite}") String sameSite) {
        this.secure = secure;
        this.sameSite = sameSite;
    }

    private static final String NAME = "session_id";
    private static final String PATH = "/api/v1/auth";
    private static final Duration TTL = Duration.ofDays(14);

    public ResponseCookie buildSessionIdCookie(String sessionId){
        return ResponseCookie.from(NAME, sessionId)
                .path(PATH)
                .maxAge(TTL)
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
