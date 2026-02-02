package com.project.budget_manager.security.service;

import com.project.budget_manager.security.entity.RefreshToken;
import com.project.budget_manager.security.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.project.budget_manager.security.exceptions.ExpiredRefreshTokenException;
import com.project.budget_manager.security.exceptions.InvalidRefreshTokenException;
import com.project.budget_manager.security.exceptions.RefreshTokenReuseDetectedException;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenCrypto refreshTokenCrypto;
    private final Duration duration = Duration.ofDays(14);

    public record IssueResult(String rawRefreshToken) {}

    public IssueResult createSession(Long userId, String deviceId, String ip, String userAgent) {
        var rawToken = refreshTokenCrypto.generateRawToken();
        var hash = refreshTokenCrypto.hash(rawToken);
        var now = Instant.now();

        refreshTokenRepository.save(RefreshToken.builder()
                .userId(userId)
                .tokenHash(hash)
                .expiresAt(now.plus(duration))
                .revoked(false)
                .deviceId(deviceId)
                .ip(ip)
                .userAgent(userAgent == null ? "unknown" : userAgent)
                .createdAt(now)
                .lastUsedAt(now)
                .build());

        return new IssueResult(rawToken);
    }

    public record RotateResult(String rawRefreshToken, Long userId, String deviceId) {}

    @Transactional(noRollbackFor = RefreshTokenReuseDetectedException.class)
    public RotateResult rotate(String rawRefreshToken, String ip, String userAgent) {
        var oldHash = refreshTokenCrypto.hash(rawRefreshToken);
        var old = refreshTokenRepository.findByTokenHashForUpdate(oldHash).orElseThrow(InvalidRefreshTokenException::new);
        var now = Instant.now();
        if (old.getExpiresAt().isBefore(now)) {
            throw new ExpiredRefreshTokenException();
        }
        if (old.isRevoked()) {
            refreshTokenRepository.revokeAllActiveByUserId(old.getUserId());
            throw new RefreshTokenReuseDetectedException();
        }

        var result = createSession(old.getUserId(), old.getDeviceId(), ip, userAgent);

        var newHash = refreshTokenCrypto.hash(result.rawRefreshToken);

        old.setRevoked(true);
        old.setRevokedAt(now);
        old.setReplacedByTokenHash(newHash);
        old.setLastUsedAt(now);

        return new RotateResult(result.rawRefreshToken, old.getUserId(), old.getDeviceId());
    }

    @Transactional
    public void revokeByRawToken(String rawRefreshToken) {
        String hash = refreshTokenCrypto.hash(rawRefreshToken);
        Optional<RefreshToken> byTokenHashForUpdate = refreshTokenRepository.findByTokenHashForUpdate(hash);
        if (byTokenHashForUpdate.isPresent()) {
            RefreshToken refreshToken = byTokenHashForUpdate.get();
            if(!refreshToken.isRevoked()) {
                Instant now = Instant.now();
                refreshToken.setRevoked(true);
                refreshToken.setRevokedAt(now);
                refreshToken.setLastUsedAt(now);
            }
        }
    }

    @Transactional
    public void revokeAllByUserId(Long userId) {
        refreshTokenRepository.revokeAllActiveByUserId(userId);
    }
    
    public List<RefreshToken> findAllByUserIdAndRevokedFalse(Long userId) {
        return refreshTokenRepository.findAllByUserIdAndRevokedFalse(userId);
    }

    @Transactional
    public void revokeAllActiveByUserIdAndDeviceId(Long userId, String deviceId) {
        refreshTokenRepository.revokeAllActiveByUserIdAndDeviceId(userId, deviceId);
    }
}
