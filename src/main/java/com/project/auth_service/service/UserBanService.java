package com.project.auth_service.service;

import com.project.auth_service.entity.User;
import com.project.auth_service.entity.UserBan;
import com.project.auth_service.enums.Role;
import com.project.auth_service.enums.UserBanEndType;
import com.project.auth_service.exceptions.InvalidUserBanException;
import com.project.auth_service.exceptions.UserAlreadyBannedException;
import com.project.auth_service.exceptions.UserBanForbiddenException;
import com.project.auth_service.exceptions.UserNotFoundException;
import com.project.auth_service.repository.UserBanRepository;
import com.project.auth_service.repository.UserRepository;
import com.project.auth_service.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserBanService {
    private final UserBanRepository userBanRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final Clock clock;

    public boolean isBanned(UUID userId) {
        return userBanRepository.existsActiveByUserId(userId, clock.instant());
    }

    public Optional<UserBan> findActiveBan(UUID userId) {
        return userBanRepository.findActiveByUserId(userId, clock.instant());
    }

    public Map<UUID, UserBan> findActiveBans(Collection<UUID> userIds) {
        if (userIds.isEmpty()) {
            return Map.of();
        }
        return userBanRepository.findActiveByUserIds(userIds, clock.instant()).stream()
                .collect(Collectors.toMap(UserBan::getUserId, Function.identity()));
    }

    @Transactional
    public UserBan ban(UUID actorUserId, UUID targetUserId, Instant expiresAt, String reason) {
        Instant now = clock.instant();
        validateBanInput(expiresAt, reason, now);

        User targetUser = findUserForUpdate(targetUserId);
        ensureCanManage(actorUserId, targetUser, true);

        userBanRepository.findCurrentByUserIdForUpdate(targetUserId).ifPresent(currentBan -> {
            if (currentBan.isActiveAt(now)) {
                throw new UserAlreadyBannedException();
            }
            currentBan.end(currentBan.getExpiresAt(), null, UserBanEndType.EXPIRED);
            userBanRepository.flush();
        });

        return userBanRepository.save(UserBan.builder()
                .userId(targetUserId)
                .createdAt(now)
                .expiresAt(expiresAt)
                .reason(reason.trim())
                .createdBy(actorUserId)
                .build());
    }

    @Transactional
    public Optional<UserBan> unban(UUID actorUserId, UUID targetUserId) {
        Instant now = clock.instant();
        User targetUser = findUserForUpdate(targetUserId);
        ensureCanManage(actorUserId, targetUser, false);

        Optional<UserBan> currentBanOptional = userBanRepository.findCurrentByUserIdForUpdate(targetUserId);
        if (currentBanOptional.isEmpty()) {
            return Optional.empty();
        }

        UserBan currentBan = currentBanOptional.get();
        if (!currentBan.isActiveAt(now)) {
            currentBan.end(currentBan.getExpiresAt(), null, UserBanEndType.EXPIRED);
            return Optional.empty();
        }

        currentBan.end(now, actorUserId, UserBanEndType.REVOKED);
        return Optional.of(currentBan);
    }

    private void validateBanInput(Instant expiresAt, String reason, Instant now) {
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw new InvalidUserBanException("Ban expiration must be in the future");
        }
        if (reason == null || reason.isBlank()) {
            throw new InvalidUserBanException("Ban reason must not be blank");
        }
        if (reason.trim().length() > 500) {
            throw new InvalidUserBanException("Ban reason must not exceed 500 characters");
        }
    }

    private void ensureCanManage(UUID actorUserId, User targetUser, boolean enforceBanProtection) {
        if (actorUserId.equals(targetUser.getId())) {
            throw new UserBanForbiddenException("Users cannot manage their own ban");
        }
        if (enforceBanProtection && targetUser.isBanProtected()) {
            throw new UserBanForbiddenException("User is protected from bans");
        }

        List<Role> actorRoles = userRoleRepository.findRolesByUserId(actorUserId);
        if (actorRoles.contains(Role.SUPER_ADMIN)) {
            return;
        }
        if (!actorRoles.contains(Role.ADMIN)) {
            throw new UserBanForbiddenException("Administrator role is required");
        }

        List<Role> targetRoles = userRoleRepository.findRolesByUserId(targetUser.getId());
        if (targetRoles.contains(Role.ADMIN) || targetRoles.contains(Role.SUPER_ADMIN)) {
            throw new UserBanForbiddenException("Only SUPER_ADMIN can manage bans for privileged users");
        }
    }

    private User findUserForUpdate(UUID userId) {
        return userRepository.findByIdForUpdate(userId).orElseThrow(UserNotFoundException::new);
    }
}
