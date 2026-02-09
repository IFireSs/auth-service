package com.project.budget_manager.security.service;

import com.project.budget_manager.security.entity.RefreshToken;
import com.project.budget_manager.security.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
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
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenCrypto refreshTokenCrypto;
    private final Duration duration = Duration.ofDays(14);

    private final boolean revoke_detect;

    private final Duration reuseGrace = Duration.ofSeconds(3);

    RefreshTokenService(RefreshTokenRepository refreshTokenRepository
                        ,RefreshTokenCrypto refreshTokenCrypto
                        ,@Value("${app.security.refresh.revoke-detect:true}") boolean revoke_detect) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenCrypto = refreshTokenCrypto;
        this.revoke_detect = revoke_detect;
    }

    public String createSession(Long userId, String sessionId, String ip, String userAgent) {
        var rawToken = refreshTokenCrypto.generateRawToken();
        var hash = refreshTokenCrypto.hash(rawToken);
        var now = Instant.now();

        refreshTokenRepository.save(RefreshToken.builder()
                .userId(userId)
                .tokenHash(hash)
                .expiresAt(now.plus(duration))
                .revoked(false)
                .sessionId(sessionId)
                .ip(ip)
                .userAgent(userAgent == null ? "unknown" : userAgent)
                .createdAt(now)
                .lastUsedAt(now)
                .build());

        return rawToken;
    }

    public record RotateResult(String rawRefreshToken, Long userId, String sessionId) {
        @Override
        public String toString() {
            return "RotateResult{" +
                    "rawRefreshToken='" + "***" + '\'' +
                    ", userId=" + userId +
                    ", sessionId='" + sessionId + '\'' +
                    '}';
        }
    }

    @Transactional(noRollbackFor = RefreshTokenReuseDetectedException.class)
    public RotateResult rotate(String rawRefreshToken, String ip, String userAgent, String sessionId) {

        var oldHash = refreshTokenCrypto.hash(rawRefreshToken);
        var old = refreshTokenRepository.findByTokenHashForUpdate(oldHash).orElseThrow(InvalidRefreshTokenException::new);
        var now = Instant.now();
        if (old.getExpiresAt().isBefore(now)) {
            throw new ExpiredRefreshTokenException();
        }
        if (revoke_detect && old.getCompromisedAt() != null) {
            throw new RefreshTokenReuseDetectedException();
        }
        boolean sessionMismatch = (sessionId == null) || !sessionId.equals(old.getSessionId());
        boolean ipMismatch = old.getIp() != null && ip != null && !ip.equals(old.getIp());
        boolean uaMismatch = old.getUserAgent() != null && userAgent != null && !userAgent.equals(old.getUserAgent());

        if (sessionMismatch && ipMismatch && uaMismatch) {
            markCompromisedAndKillAllSessionsOnce(old.getUserId(), now, "SESSION_IP_UA_MISMATCH");
            throw new RefreshTokenReuseDetectedException();
        }else if(sessionMismatch && ipMismatch){
            markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, "SESSION_IP_MISMATCH");
            throw new RefreshTokenReuseDetectedException();
        }else if(sessionMismatch) {
            markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, "SESSION_MISMATCH");
            throw new RefreshTokenReuseDetectedException();
        }
        if (revoke_detect && old.isRevoked()) {
            if (old.getRevokedAt() != null
                    && old.getReplacedByTokenHash() != null
                    && Duration.between(old.getRevokedAt(), now).compareTo(reuseGrace) <= 0) {

                old.setLastUsedAt(now);
                return new RotateResult(null, old.getUserId(), old.getSessionId());
            }

            markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, "REUSE_DETECTED");
            throw new RefreshTokenReuseDetectedException();
        }

        var result = createSession(old.getUserId(), old.getSessionId(), ip, userAgent);

        var newHash = refreshTokenCrypto.hash(result);

        if(!revoke_detect){
            refreshTokenRepository.deleteById(old.getId());
        }else {
            old.setRevoked(true);
            old.setRevokedAt(now);
            old.setReplacedByTokenHash(newHash);
            old.setLastUsedAt(now);
        }

        return new RotateResult(result, old.getUserId(), old.getSessionId());
    }

    @Transactional
    public void revokeByRawToken(String rawRefreshToken) {
        String hash = refreshTokenCrypto.hash(rawRefreshToken);
        if(!revoke_detect){
            refreshTokenRepository.deleteByTokenHash(hash);
            return;
        }
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
    public void revokeAllByUserId(Long userId, Instant now) {
        if(!revoke_detect){
            refreshTokenRepository.deleteAllByUserId(userId);
        }else{
            refreshTokenRepository.revokeAllActiveByUserId(userId, now);
        }

    }
    
    public List<RefreshToken> findAllByUserIdAndRevokedFalse(Long userId) {
        return refreshTokenRepository.findAllByUserIdAndRevokedFalse(userId);
    }

    @Transactional
    public void revokeAllActiveByUserIdAndSessionId(Long userId, String sessionId, Instant now) {
        if(!revoke_detect){
            refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
        }else {
            refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
        }
    }

    private void markCompromisedAndKillSessionOnce(Long userId, String sessionId, Instant now, String reason) {
        int first = refreshTokenRepository.markSessionCompromisedOnce(userId, sessionId, now, reason);

        if (first > 0) {
            if (revoke_detect) {
                refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
            } else {
                refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
            }
        }
    }

    private void markCompromisedAndKillAllSessionsOnce(Long userId, Instant now, String reason) {
        int first = refreshTokenRepository.markAllSessionsCompromisedOnce(userId, now, reason);

        if (first > 0) {
            if (revoke_detect) {
                refreshTokenRepository.revokeAllActiveByUserId(userId, now);
            } else {
                refreshTokenRepository.deleteAllByUserId(userId);
            }
        }
    }
}
