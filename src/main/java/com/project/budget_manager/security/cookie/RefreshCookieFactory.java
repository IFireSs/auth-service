package com.project.budget_manager.security.cookie;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RefreshCookieFactory {

    private final boolean secure;

    public RefreshCookieFactory(@Value("${app.security.cookies.secure:false}") boolean secure) {
        this.secure = secure;
    }

    private static final String NAME = "refresh_token";
    private static final String PATH = "/api/v1/auth";
    private static final Duration TTL = Duration.ofDays(14);

    public ResponseCookie buildRefreshCookie(String rawRefreshToken){
        return ResponseCookie.from(NAME, rawRefreshToken)
                .path(PATH)
                .maxAge(TTL)
                .sameSite("Lax")
                .httpOnly(true)
                .secure(false)
                .build();
    }

    public ResponseCookie clearRefreshCookie(){
        return ResponseCookie.from(NAME, "")
                .path(PATH)
                .maxAge(0)
                .sameSite("Lax")
                .httpOnly(true)
                .secure(secure)
                .build();
    }
}
