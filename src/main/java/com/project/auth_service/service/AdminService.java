package com.project.auth_service.service;

import com.project.auth_service.api.dto.AdminUserResponse;
import com.project.auth_service.api.dto.AuditEventResponse;
import com.project.auth_service.api.dto.SessionResponse;
import com.project.auth_service.api.dto.UserBanResponse;
import com.project.auth_service.entity.User;
import com.project.auth_service.entity.UserBan;
import com.project.auth_service.entity.UserRoleEntity;
import com.project.auth_service.entity.UserRoleId;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.enums.Role;
import com.project.auth_service.exceptions.UserNotFoundException;
import com.project.auth_service.repository.UserRepository;
import com.project.auth_service.repository.UserRoleRepository;
import com.project.auth_service.service.dto.AuditEventFilter;
import com.project.auth_service.service.dto.OffsetBasedPageRequest;
import com.project.auth_service.service.dto.SessionFilter;
import com.project.auth_service.service.dto.UserFilter;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AdminService {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RefreshTokenService refreshTokenService;
    private final AuditEventService auditEventService;
    private final SessionResponseMapper sessionResponseMapper;
    private final UserBanService userBanService;

    public List<AdminUserResponse> listUsers(UserFilter filter, int limit, int offset) {
        Sort sort = Sort.by("createdAt").ascending().and(Sort.by("id").ascending());

        List<User> users = userRepository.findAll(
                        userSpecification(filter),
                        OffsetBasedPageRequest.capped(limit, offset, sort)
                )
                .stream()
                .toList();

        Map<UUID, List<Role>> rolesByUserId = rolesByUserId(users);
        Map<UUID, UserBan> bansByUserId = userBanService.findActiveBans(users.stream().map(User::getId).toList());
        return users.stream()
                .map(user -> toAdminUserResponse(
                        user,
                        rolesByUserId.getOrDefault(user.getId(), List.of()),
                        bansByUserId.get(user.getId())
                ))
                .toList();
    }

    public AdminUserResponse getUser(UUID userId) {
        return toAdminUserResponse(findUser(userId));
    }

    public List<SessionResponse> listUserSessions(UUID userId, SessionFilter filter, int limit, int offset) {
        ensureUserExists(userId);
        Instant now = Instant.now();
        return refreshTokenService.findAllByUserId(userId, filter, limit, offset).stream()
                .map(refreshToken -> sessionResponseMapper.toResponse(refreshToken, now))
                .toList();
    }

    public List<AuditEventResponse> listAuditEvents(AuditEventFilter filter, int limit, int offset) {
        return auditEventService.listEvents(filter, limit, offset);
    }

    @Transactional
    public void logoutUserEverywhere(UUID actorUserId, UUID userId) {
        ensureUserExists(userId);
        refreshTokenService.revokeAllByUserId(userId, Instant.now());
        auditEventService.record(AuditEventType.ALL_SESSIONS_REVOKED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .targetUserId(userId)
                .build());
    }

    @Transactional
    public void revokeUserSession(UUID actorUserId, UUID userId, String sessionId) {
        ensureUserExists(userId);
        refreshTokenService.revokeAllActiveByUserIdAndSessionId(userId, sessionId, Instant.now());
        auditEventService.record(AuditEventType.SESSION_REVOKED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .targetUserId(userId)
                .sessionId(sessionId)
                .build());
    }

    @Transactional
    public AdminUserResponse banUser(UUID actorUserId, UUID userId, Instant expiresAt, String reason) {
        UserBan ban = userBanService.ban(actorUserId, userId, expiresAt, reason);
        refreshTokenService.revokeAllByUserIdPreservingState(userId, Instant.now());
        auditEventService.record(AuditEventType.USER_BANNED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .targetUserId(userId)
                .details(banDetails(ban))
                .build());
        return toAdminUserResponse(findUser(userId));
    }

    @Transactional
    public AdminUserResponse unbanUser(UUID actorUserId, UUID userId) {
        userBanService.unban(actorUserId, userId).ifPresent(ban ->
                auditEventService.record(AuditEventType.USER_UNBANNED, AuditEventService.AuditEventCommand.builder()
                        .actorUserId(actorUserId)
                        .targetUserId(userId)
                        .details(Map.of("banId", ban.getId().toString()))
                        .build())
        );
        return toAdminUserResponse(findUser(userId));
    }

    @Transactional
    public void grantAdmin(UUID actorUserId, UUID userId) {
        ensureUserExists(userId);
        userRoleRepository.save(new UserRoleEntity(new UserRoleId(userId, Role.ADMIN)));
        auditEventService.record(AuditEventType.ADMIN_ROLE_GRANTED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .targetUserId(userId)
                .details(Map.of("role", Role.ADMIN.name()))
                .build());
    }

    @Transactional
    public void revokeAdmin(UUID actorUserId, UUID userId) {
        ensureUserExists(userId);
        Instant now = Instant.now();
        userRoleRepository.deleteById(new UserRoleId(userId, Role.ADMIN));
        refreshTokenService.revokeAllByUserId(userId, now);
        auditEventService.record(AuditEventType.ADMIN_ROLE_REVOKED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(actorUserId)
                .targetUserId(userId)
                .details(java.util.Map.of(
                        "role", Role.ADMIN.name(),
                        "sessionsRevoked", true
                ))
                .build());
    }

    private AdminUserResponse toAdminUserResponse(User user) {
        return toAdminUserResponse(
                user,
                userRoleRepository.findRolesByUserId(user.getId()),
                userBanService.findActiveBan(user.getId()).orElse(null)
        );
    }

    private AdminUserResponse toAdminUserResponse(User user, List<Role> roles, UserBan activeBan) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getCreatedAt(),
                user.isBanProtected(),
                toUserBanResponse(activeBan),
                roles
        );
    }

    private UserBanResponse toUserBanResponse(UserBan ban) {
        if (ban == null) {
            return null;
        }
        return new UserBanResponse(
                ban.getId(),
                ban.getCreatedAt(),
                ban.getExpiresAt(),
                ban.getReason(),
                ban.getCreatedBy()
        );
    }

    private Map<String, Object> banDetails(UserBan ban) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("banId", ban.getId().toString());
        details.put("permanent", ban.getExpiresAt() == null);
        details.put("reason", ban.getReason());
        details.put("sessionsRevoked", true);
        if (ban.getExpiresAt() != null) {
            details.put("expiresAt", ban.getExpiresAt().toString());
        }
        return details;
    }

    private Map<UUID, List<Role>> rolesByUserId(List<User> users) {
        List<UUID> userIds = users.stream()
                .map(User::getId)
                .toList();
        if (userIds.isEmpty()) {
            return Map.of();
        }
        return userRoleRepository.findRolesByUserIds(userIds).stream()
                .collect(Collectors.groupingBy(
                        UserRoleRepository.UserRoleView::getUserId,
                        Collectors.mapping(UserRoleRepository.UserRoleView::getRole, Collectors.toList())
                ));
    }

    private Specification<User> userSpecification(UserFilter filter) {
        return (root, query, criteriaBuilder) -> {
            if (filter == null) {
                return criteriaBuilder.conjunction();
            }

            List<Predicate> predicates = new ArrayList<>();

            if (hasText(filter.query())) {
                String likeQuery = "%" + filter.query().trim().toLowerCase() + "%";
                predicates.add(criteriaBuilder.or(
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("username")), likeQuery),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), likeQuery)
                ));
            }

            if (filter.role() != null) {
                assert query != null;
                var subquery = query.subquery(UUID.class);
                var userRoleRoot = subquery.from(UserRoleEntity.class);
                subquery.select(userRoleRoot.get("id").get("userId"))
                        .where(
                                criteriaBuilder.equal(userRoleRoot.get("id").get("userId"), root.get("id")),
                                criteriaBuilder.equal(userRoleRoot.get("id").get("role"), filter.role())
                        );
                predicates.add(criteriaBuilder.exists(subquery));
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private User findUser(UUID userId) {
        return userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
    }

    private void ensureUserExists(UUID userId) {
        if (!userRepository.existsById(userId)) {
            throw new UserNotFoundException();
        }
    }
}
