package com.project.auth_service.repository;

import com.project.auth_service.entity.UserBan;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserBanRepository extends JpaRepository<UserBan, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select ban
            from UserBan ban
            where ban.userId = :userId
              and ban.endedAt is null
            """)
    Optional<UserBan> findCurrentByUserIdForUpdate(@Param("userId") UUID userId);

    @Query("""
            select ban
            from UserBan ban
            where ban.userId = :userId
              and ban.endedAt is null
              and (ban.expiresAt is null or ban.expiresAt > :now)
            """)
    Optional<UserBan> findActiveByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    @Query("""
            select ban
            from UserBan ban
            where ban.userId in :userIds
              and ban.endedAt is null
              and (ban.expiresAt is null or ban.expiresAt > :now)
            """)
    List<UserBan> findActiveByUserIds(@Param("userIds") Collection<UUID> userIds, @Param("now") Instant now);

    @Query("""
            select count(ban) > 0
            from UserBan ban
            where ban.userId = :userId
              and ban.endedAt is null
              and (ban.expiresAt is null or ban.expiresAt > :now)
            """)
    boolean existsActiveByUserId(@Param("userId") UUID userId, @Param("now") Instant now);
}
