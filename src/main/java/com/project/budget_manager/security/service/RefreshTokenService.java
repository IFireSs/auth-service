package com.project.budget_manager.security.service;

import com.project.budget_manager.security.config.AppSecurityProperties;
import com.project.budget_manager.security.entity.RefreshToken;
import com.project.budget_manager.security.exceptions.RefreshTokenAlreadyProcessedException;
import com.project.budget_manager.security.repository.RefreshTokenRepository;
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
    private static final String UNKNOWN_USER_AGENT = "unknown";

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenCrypto refreshTokenCrypto;
    private final RefreshReplayCrypto refreshReplayCrypto;
    private final Duration refreshTtl;
    private final boolean revokeDetect;
    private final Duration reuseGrace;
    private final boolean requireSessionId;
    private final boolean bindToUserAgent;
    private final boolean bindToIp;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository
                        ,RefreshTokenCrypto refreshTokenCrypto
                        ,RefreshReplayCrypto refreshReplayCrypto
                        ,AppSecurityProperties securityProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenCrypto = refreshTokenCrypto;
        this.refreshReplayCrypto = refreshReplayCrypto;
        this.refreshTtl = securityProperties.refresh().ttl();
        this.revokeDetect = securityProperties.refresh().revokeDetect();
        this.reuseGrace = securityProperties.refresh().reuseGrace();
        this.requireSessionId = securityProperties.refresh().clientBinding().requireSessionId();
        this.bindToUserAgent = securityProperties.refresh().clientBinding().bindToUserAgent();
        this.bindToIp = securityProperties.refresh().clientBinding().bindToIp();
    }

    public String createSession(Long userId, String sessionId, String ip, String userAgent) {
        var rawToken = refreshTokenCrypto.generateRawToken();
        var hash = refreshTokenCrypto.hash(rawToken);
        var now = Instant.now();
        String normalizedUserAgent = normalizeUserAgent(userAgent);

        refreshTokenRepository.save(RefreshToken.builder()
                .userId(userId)
                .tokenHash(hash)
                .expiresAt(now.plus(refreshTtl))
                .revoked(false)
                .sessionId(sessionId)
                .ip(ip)
                .userAgent(normalizedUserAgent)
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
    public RotateResult rotate(String rawRefreshToken,
                               String ip,
                               String userAgent,
                               String sessionId,
                               String refreshAttemptId) {

        var oldHash = refreshTokenCrypto.hash(rawRefreshToken);
        var old = refreshTokenRepository.findByTokenHashForUpdate(oldHash).orElseThrow(InvalidRefreshTokenException::new);
        var now = Instant.now();
        String normalizedAttemptId = normalizeAttemptId(refreshAttemptId);
        String normalizedSessionId = normalizeSessionId(sessionId);
        String normalizedUserAgent = normalizeUserAgent(userAgent);
        if (old.getExpiresAt().isBefore(now)) {
            throw new ExpiredRefreshTokenException();
        }
        if (revokeDetect && old.getCompromisedAt() != null) {
            throw new RefreshTokenReuseDetectedException();
        }
        if (requireSessionId && normalizedSessionId == null) {
            throw new InvalidRefreshTokenException();
        }

        boolean sessionMismatch = normalizedSessionId != null && !normalizedSessionId.equals(old.getSessionId());
        boolean ipMismatch = bindToIp && isValueMismatch(old.getIp(), ip);
        boolean uaMismatch = bindToUserAgent && isValueMismatch(old.getUserAgent(), normalizedUserAgent);

        if (sessionMismatch || ipMismatch || uaMismatch) {
            if (sessionMismatch && ipMismatch && uaMismatch) {
                markCompromisedAndKillAllSessionsOnce(old.getUserId(), now, mismatchReason(sessionMismatch, ipMismatch, uaMismatch));
            } else {
                markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, mismatchReason(sessionMismatch, ipMismatch, uaMismatch));
            }
            throw new RefreshTokenReuseDetectedException();
        }
        if (revokeDetect && old.isRevoked()) {
            if (old.getRevokedAt() != null
                    && old.getReplacedByTokenHash() != null
                    && Duration.between(old.getRevokedAt(), now).compareTo(reuseGrace) <= 0) {
                if (sameAttempt(old, normalizedAttemptId, now)) {
                    old.setLastUsedAt(now);
                    return new RotateResult(
                            refreshReplayCrypto.decrypt(old.getRotationResultTokenCipher()),
                            old.getUserId(),
                            old.getSessionId()
                    );
                }
                throw new RefreshTokenAlreadyProcessedException();
            }
            if (old.getRevokedAt() != null
                    && old.getReplacedByTokenHash() != null
                    && old.getRotationResultExpiresAt() != null
                    && old.getRotationResultExpiresAt().isAfter(now)) {
                throw new RefreshTokenAlreadyProcessedException();
            }

            markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, "REUSE_DETECTED");
            throw new RefreshTokenReuseDetectedException();
        }

        var result = createSession(old.getUserId(), old.getSessionId(), ip, normalizedUserAgent);

        var newHash = refreshTokenCrypto.hash(result);

        if(!revokeDetect){
            refreshTokenRepository.deleteById(old.getId());
        }else {
            old.setRevoked(true);
            old.setRevokedAt(now);
            old.setReplacedByTokenHash(newHash);
            old.setLastUsedAt(now);
            old.setRotationAttemptId(normalizedAttemptId);
            old.setRotationResultTokenCipher(normalizedAttemptId == null ? null : refreshReplayCrypto.encrypt(result));
            old.setRotationResultExpiresAt(normalizedAttemptId == null ? null : now.plus(reuseGrace));
        }

        return new RotateResult(result, old.getUserId(), old.getSessionId());
    }

    @Transactional
    public void revokeByRawToken(String rawRefreshToken) {
        String hash = refreshTokenCrypto.hash(rawRefreshToken);
        if(!revokeDetect){
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
        if(!revokeDetect){
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
        if(!revokeDetect){
            refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
        }else {
            refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
        }
    }

    private void markCompromisedAndKillSessionOnce(Long userId, String sessionId, Instant now, String reason) {
        int first = refreshTokenRepository.markSessionCompromisedOnce(userId, sessionId, now, reason);

        if (first > 0) {
            if (revokeDetect) {
                refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
            } else {
                refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
            }
        }
    }

    private void markCompromisedAndKillAllSessionsOnce(Long userId, Instant now, String reason) {
        int first = refreshTokenRepository.markAllSessionsCompromisedOnce(userId, now, reason);

        if (first > 0) {
            if (revokeDetect) {
                refreshTokenRepository.revokeAllActiveByUserId(userId, now);
            } else {
                refreshTokenRepository.deleteAllByUserId(userId);
            }
        }
    }

    private String normalizeAttemptId(String refreshAttemptId) {
        if (refreshAttemptId == null || refreshAttemptId.isBlank()) {
            return null;
        }
        return refreshAttemptId.trim();
    }

    private String normalizeSessionId(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        return sessionId.trim();
    }

    private String normalizeUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN_USER_AGENT;
        }
        return userAgent.trim();
    }

    private boolean isValueMismatch(String actual, String candidate) {
        return actual != null && candidate != null && !actual.equals(candidate);
    }

    private String mismatchReason(boolean sessionMismatch, boolean ipMismatch, boolean uaMismatch) {
        StringBuilder reason = new StringBuilder();
        if (sessionMismatch) {
            reason.append("SESSION");
        }
        if (ipMismatch) {
            appendReasonSeparator(reason);
            reason.append("IP");
        }
        if (uaMismatch) {
            appendReasonSeparator(reason);
            reason.append("UA");
        }
        reason.append("_MISMATCH");
        return reason.toString();
    }

    private void appendReasonSeparator(StringBuilder reason) {
        if (!reason.isEmpty()) {
            reason.append('_');
        }
    }

    private boolean sameAttempt(RefreshToken refreshToken, String refreshAttemptId, Instant now) {
        return refreshAttemptId != null
                && refreshAttemptId.equals(refreshToken.getRotationAttemptId())
                && refreshToken.getRotationResultTokenCipher() != null
                && refreshToken.getRotationResultExpiresAt() != null
                && !refreshToken.getRotationResultExpiresAt().isBefore(now);
    }
}
