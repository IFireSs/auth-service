package com.project.budget_manager.security.repository;

import com.project.budget_manager.security.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
        set t.revoked = true,
            t.revokedAt = CURRENT_TIMESTAMP
        where t.userId = :userId
        and t.revoked = false
        """)
    int revokeAllActiveByUserId(@Param("userId") Long userId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
        set t.revoked = true,
            t.revokedAt = CURRENT_TIMESTAMP
        where t.userId = :userId
        and t.deviceId = :deviceId
        and t.revoked = false
        """)
    int revokeAllActiveByUserIdAndDeviceId(@Param("userId") Long userId,
                                           @Param("deviceId") String deviceId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshToken t where t.tokenHash = :hash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("hash") String hash);

    List<RefreshToken> findAllByUserIdAndRevokedFalse(Long userId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
