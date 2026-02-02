package com.project.budget_manager.security.service;

import com.project.budget_manager.security.api.dto.SessionResponse;
import com.project.budget_manager.security.entity.RefreshToken;
import com.project.budget_manager.security.exceptions.BadCredentialsException;
import com.project.budget_manager.security.port.AuthUser;
import com.project.budget_manager.security.port.AuthUserProvider;
import com.project.budget_manager.security.port.AuthUserRegistrar;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final AuthUserRegistrar authUserRegistrar;
    private final AuthUserProvider authUserProvider;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;

    public record AuthResult(String accessToken, String rawRefreshToken) {}

    public AuthResult register(String username,
                               String email,
                               String password,
                               String deviceId,
                               String ip,
                               String userAgent){

        String passwordHash = passwordEncoder.encode(password);
        AuthUser authUser = authUserRegistrar.register(username, email, passwordHash);

        Long userId = authUser.id();
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles());
        RefreshTokenService.IssueResult issue = refreshTokenService.createSession(userId, deviceId, ip, userAgent);
        return new AuthResult(accessToken, issue.rawRefreshToken());
    }

    public AuthResult login(String username,
                     String password,
                     String deviceId,
                     String ip,
                     String userAgent) {

        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        }catch (AuthenticationException e){
            throw new BadCredentialsException();
        }

        AuthUser authUser = authUserProvider.findByUsername(username).orElseThrow(BadCredentialsException::new);
        Long userId = authUser.id();
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles());
        RefreshTokenService.IssueResult issue = refreshTokenService.createSession(userId, deviceId, ip, userAgent);
        return new AuthResult(accessToken, issue.rawRefreshToken());
    }

    public AuthResult refresh(String rawRefreshToken,
                       String ip,
                       String userAgent) {
        RefreshTokenService.RotateResult rotateResult = refreshTokenService.rotate(rawRefreshToken, ip, userAgent);

        Long userId = rotateResult.userId();
        AuthUser authUser = authUserProvider.findById(userId).orElseThrow(BadCredentialsException::new);
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles());
        return new AuthResult(accessToken, rotateResult.rawRefreshToken());
    }

    public void logout(String rawRefreshToken){
        if(rawRefreshToken == null){
            return;
        }
        refreshTokenService.revokeByRawToken(rawRefreshToken);
    }

    public void logoutAll(Number userId){
        refreshTokenService.revokeAllByUserId(userId.longValue());
    }

    public void logoutDevice(Long userId, String deviceId){
        refreshTokenService.revokeAllActiveByUserIdAndDeviceId(userId, deviceId);
    }

    public List<SessionResponse> sessions(Long userId){
        List<RefreshToken> allByUserIdAndRevokedFalse = refreshTokenService.findAllByUserIdAndRevokedFalse(userId);
        return allByUserIdAndRevokedFalse.stream().map(refreshToken -> SessionResponse.builder()
                .deviceId(refreshToken.getDeviceId())
                .ip(refreshToken.getIp())
                .userAgent(refreshToken.getUserAgent())
                .createdAt(refreshToken.getCreatedAt())
                .lastUsedAt(refreshToken.getLastUsedAt())
                .expiresAt(refreshToken.getExpiresAt())
                .build()).toList();

    }
}
