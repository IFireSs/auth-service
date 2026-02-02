package com.project.budget_manager.security.api;

import com.project.budget_manager.security.api.dto.LoginRequest;
import com.project.budget_manager.security.api.dto.RegisterRequest;
import com.project.budget_manager.security.api.dto.SessionResponse;
import com.project.budget_manager.security.api.dto.TokenResponse;
import com.project.budget_manager.security.exceptions.InvalidRefreshTokenException;
import com.project.budget_manager.security.service.AuthService;
import com.project.budget_manager.security.cookie.RefreshCookieFactory;
import jakarta.servlet.http.HttpServletRequest;
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

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest registerRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent) {

        AuthService.AuthResult authResult = authService.register(registerRequest.getUsername(),
                registerRequest.getEmail(),
                registerRequest.getPassword(),
                UUID.randomUUID().toString(),
                request.getRemoteAddr(),
                userAgent);
        ResponseCookie responseCookie = refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(TokenResponse.builder()
                        .accessToken(authResult.accessToken())
                        .build());
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent) {

        AuthService.AuthResult authResult = authService.login(loginRequest.getUsername(),
                loginRequest.getPassword(),
                UUID.randomUUID().toString(),
                request.getRemoteAddr(),
                userAgent);
        ResponseCookie responseCookie = refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(TokenResponse.builder()
                    .accessToken(authResult.accessToken())
                    .build());
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            HttpServletRequest request,
            @RequestHeader(value = "User-Agent", required = false) String userAgent){

        if(refreshToken == null){
            throw new InvalidRefreshTokenException();
        }

        AuthService.AuthResult authResult = authService.refresh(refreshToken, request.getRemoteAddr(), userAgent);
        ResponseCookie responseCookie = refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(TokenResponse.builder()
                        .accessToken(authResult.accessToken())
                        .build());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken){
        authService.logout(refreshToken);
        ResponseCookie responseCookie = refreshCookieFactory.clearRefreshCookie();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt){
        Long userId = ((Number) jwt.getClaim("uid")).longValue();
        authService.logoutAll(userId);
        ResponseCookie responseCookie = refreshCookieFactory.clearRefreshCookie();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }

    @PostMapping("/logout-device/{deviceId}")
    public ResponseEntity<Void> logoutDevice(@AuthenticationPrincipal Jwt jwt,
                                             @PathVariable String deviceId,
                                             @RequestHeader(name = "X-Device-Id", required = false) String currentDeviceId){
        Long userId = ((Number) jwt.getClaim("uid")).longValue();
        authService.logoutDevice(userId, deviceId);
        if (!deviceId.equals(currentDeviceId)) {
            return ResponseEntity.noContent().build();
        }
        ResponseCookie responseCookie = refreshCookieFactory.clearRefreshCookie();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
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
}
