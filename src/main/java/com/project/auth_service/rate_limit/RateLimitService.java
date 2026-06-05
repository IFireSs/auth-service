package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RateLimitService {
    private final RateLimitProperties properties;
    private final RateLimitBackend backend;

    public RateLimitBackend.Result tryConsume(Scope scope, String key) {
        return backend.tryConsume(List.of(new RateLimitBackend.Request(scope, key, limitFor(scope))));
    }

    public RateLimitBackend.Result tryConsumeLogin(String username, String ip) {
        return backend.tryConsume(List.of(
                new RateLimitBackend.Request(Scope.LOGIN_IP, ip, properties.login()),
                new RateLimitBackend.Request(Scope.LOGIN_USERNAME_IP, username + ":" + ip, properties.login())
        ));
    }

    private RateLimitProperties.Limit limitFor(Scope scope) {
        return switch (scope) {
            case LOGIN_IP, LOGIN_USERNAME_IP -> properties.login();
            case REGISTER -> properties.register();
            case REFRESH -> properties.refresh();
            case ADMIN -> properties.admin();
        };
    }

    public enum Scope {
        LOGIN_IP("login:ip"),
        LOGIN_USERNAME_IP("login:username-ip"),
        REGISTER("register"),
        REFRESH("refresh"),
        ADMIN("admin");

        private final String keyPrefix;

        Scope(String keyPrefix) {
            this.keyPrefix = keyPrefix;
        }

        public String keyPrefix() {
            return keyPrefix;
        }

        public boolean isLogin() {
            return this == LOGIN_IP || this == LOGIN_USERNAME_IP;
        }
    }
}
