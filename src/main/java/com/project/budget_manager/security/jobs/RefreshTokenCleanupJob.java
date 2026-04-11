package com.project.budget_manager.security.jobs;

import com.project.budget_manager.security.config.AppSecurityProperties;
import com.project.budget_manager.security.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenCleanupJob {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AppSecurityProperties props;

    @Scheduled(cron = "${app.security.refresh.cleanup.cron}")
    @Transactional
    public void cleanup() {
        if (!props.refresh().cleanup().enabled()) return;

        Instant cutoff = Instant.now().minus(props.refresh().cleanup().retention());
        int deleted = refreshTokenRepository.deleteExpiredBefore(cutoff);

        if (deleted > 0) {
            log.info("Refresh token cleanup: deleted {} rows (cutoff={})", deleted, cutoff);
        }
    }
}
