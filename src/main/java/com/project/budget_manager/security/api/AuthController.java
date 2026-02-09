package com.project.budget_manager.security.api;

import com.project.budget_manager.security.api.dto.LoginRequest;
import com.project.budget_manager.security.api.dto.RegisterRequest;
import com.project.budget_manager.security.api.dto.SessionResponse;
import com.project.budget_manager.security.api.dto.TokenResponse;
import com.project.budget_manager.security.cookie.SessionIdCookieFactory;
import com.project.budget_manager.security.exceptions.InvalidRefreshTokenException;
import com.project.budget_manager.security.service.AuthService;
import com.project.budget_manager.security.cookie.RefreshCookieFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshCookieFactory refreshCookieFactory;
    private final SessionIdCookieFactory sessionIdCookieFactory;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegisterRequest registerRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent) {
        AuthService.AuthResult authResult = authService.register(
                registerRequest.getUsername(),
                registerRequest.getEmail(),
                registerRequest.getPassword(),
                UUID.randomUUID().toString(),
                request.getRemoteAddr(),
                userAgent);

        return getOkAuthResponseEntity(authResult);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent) {

        AuthService.AuthResult authResult = authService.login(
                loginRequest.getUsername(),
                loginRequest.getPassword(),
                UUID.randomUUID().toString(),
                request.getRemoteAddr(),
                userAgent);
        return getOkAuthResponseEntity(authResult);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            @CookieValue(name = "session_id", required = false) String sessionId,
            HttpServletRequest request,
            @RequestHeader(value = "User-Agent", required = false) String userAgent){

        if(refreshToken == null){
            throw new InvalidRefreshTokenException();
        }

        AuthService.AuthResult authResult = authService.refresh(refreshToken, request.getRemoteAddr(), userAgent, sessionId);

        var refreshResult = ResponseEntity.ok();

        if (authResult.rawRefreshToken() != null) {
            refreshResult.header(HttpHeaders.SET_COOKIE,
                    refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken()).toString());
        }

        return refreshResult.body(TokenResponse.builder()
                .accessToken(authResult.accessToken())
                .build());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken){
        authService.logout(refreshToken);
        ResponseCookie refreshCookie = refreshCookieFactory.clearRefreshCookie();
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.clearSessionIdCookie();
        return ResponseEntity.noContent()
                .headers(header -> {
                    header.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
                    header.add(HttpHeaders.SET_COOKIE, sessionIdCookie.toString());
                })
                .build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt){
        Long userId = ((Number) jwt.getClaim("uid")).longValue();
        authService.logoutAll(userId);
        ResponseCookie refreshCookie = refreshCookieFactory.clearRefreshCookie();
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.clearSessionIdCookie();
        return ResponseEntity.noContent()
                .headers(header -> {
                    header.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
                    header.add(HttpHeaders.SET_COOKIE, sessionIdCookie.toString());
                })
                .build();
    }

    @PostMapping("/logout-session/{sessionId}")
    public ResponseEntity<Void> logoutSession(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable String sessionId){
        Long userId = ((Number) jwt.getClaim("uid")).longValue();
        authService.logoutSession(userId, sessionId);
        String currentSessionId = jwt.getClaimAsString("sid");
        if (!sessionId.equals(currentSessionId)) {
            return ResponseEntity.noContent().build();
        }
        ResponseCookie refreshCookie = refreshCookieFactory.clearRefreshCookie();
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.clearSessionIdCookie();
        return ResponseEntity.noContent()
                .headers(header -> {
                    header.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
                    header.add(HttpHeaders.SET_COOKIE, sessionIdCookie.toString());
                })
                .build();
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> sessions(@AuthenticationPrincipal Jwt jwt){
        Long userId = ((Number) jwt.getClaim("uid")).longValue();
        return ResponseEntity.ok().body(authService.sessions(userId));
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken());
    }


    private ResponseEntity<TokenResponse> getOkAuthResponseEntity(AuthService.AuthResult authResult) {
        ResponseCookie refreshCookie = refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken());
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.buildSessionIdCookie(authResult.sessionId());
        return ResponseEntity.ok()
                .headers(header -> {
                    header.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
                    header.add(HttpHeaders.SET_COOKIE, sessionIdCookie.toString());
                })
                .body(TokenResponse.builder()
                        .accessToken(authResult.accessToken())
                        .build());
    }
}
