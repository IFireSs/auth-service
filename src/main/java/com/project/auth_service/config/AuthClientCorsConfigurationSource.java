package com.project.auth_service.config;

import com.project.auth_service.service.AuthClientService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Component("corsConfigurationSource")
@RequiredArgsConstructor
public class AuthClientCorsConfigurationSource implements CorsConfigurationSource {
    private static final long MAX_AGE_SECONDS = 1800;

    private final AuthClientService authClientService;

    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        String origin = request.getHeader(HttpHeaders.ORIGIN);
        if (!authClientService.isOriginAllowedForAnyActiveClient(origin)) {
            return null;
        }

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(origin.trim()));
        config.setAllowedMethods(List.of(
                HttpMethod.GET.name(),
                HttpMethod.POST.name(),
                HttpMethod.PUT.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.OPTIONS.name()
        ));
        config.setAllowedHeaders(List.of(
                HttpHeaders.AUTHORIZATION,
                HttpHeaders.CONTENT_TYPE,
                HttpHeaders.ACCEPT,
                "X-XSRF-TOKEN",
                "X-Refresh-Attempt-Id"
        ));
        config.setAllowCredentials(true);
        config.setMaxAge(MAX_AGE_SECONDS);
        return config;
    }
}
