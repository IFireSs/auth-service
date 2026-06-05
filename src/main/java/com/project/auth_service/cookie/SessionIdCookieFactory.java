package com.project.auth_service.cookie;

import com.project.auth_service.config.AppSecurityProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class SessionIdCookieFactory extends AuthCookieSupport {
    private static final String NAME = "session_id";

    public SessionIdCookieFactory(AppSecurityProperties securityProperties) {
        super(securityProperties);
    }

    public ResponseCookie buildSessionIdCookie(String sessionId){
        return buildCookie(NAME, sessionId);
    }

    public ResponseCookie clearSessionIdCookie(){
        return clearCookie(NAME);
    }
}
