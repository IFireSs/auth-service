package com.project.auth_service.cookie;

import com.project.auth_service.config.AppSecurityProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class RefreshCookieFactory extends AuthCookieSupport {
    private static final String NAME = "refresh_token";

    public RefreshCookieFactory(AppSecurityProperties securityProperties) {
        super(securityProperties);
    }

    public ResponseCookie buildRefreshCookie(String rawRefreshToken){
        return buildCookie(NAME, rawRefreshToken);
    }

    public ResponseCookie clearRefreshCookie(){
        return clearCookie(NAME);
    }
}
