package com.project.auth_service.api;

import com.project.auth_service.api.dto.AuditEventResponse;
import com.project.auth_service.api.dto.AdminUserResponse;
import com.project.auth_service.api.dto.AuthClientCreateRequest;
import com.project.auth_service.api.dto.AuthClientResponse;
import com.project.auth_service.api.dto.AuthClientUpdateRequest;
import com.project.auth_service.api.dto.SessionResponse;
import com.project.auth_service.api.dto.UserBanRequest;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.enums.Role;
import com.project.auth_service.enums.SessionStatus;
import com.project.auth_service.service.AdminService;
import com.project.auth_service.service.AuthClientService;
import com.project.auth_service.service.JwtClaims;
import com.project.auth_service.service.dto.AuditEventFilter;
import com.project.auth_service.service.dto.SessionFilter;
import com.project.auth_service.service.dto.UserFilter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final AdminService adminService;
    private final AuthClientService authClientService;

    @GetMapping("/users")
    public List<AdminUserResponse> listUsers(@RequestParam(defaultValue = "50") int limit,
                                             @RequestParam(defaultValue = "0") int offset,
                                             @RequestParam(required = false) String query,
                                             @RequestParam(required = false) Role role) {
        return adminService.listUsers(new UserFilter(query, role), limit, offset);
    }

    @GetMapping("/users/{userId}")
    public AdminUserResponse getUser(@PathVariable UUID userId) {
        return adminService.getUser(userId);
    }

    @GetMapping("/users/{userId}/sessions")
    public List<SessionResponse> listUserSessions(@PathVariable UUID userId,
                                                  @RequestParam(defaultValue = "50") int limit,
                                                  @RequestParam(defaultValue = "0") int offset,
                                                  @RequestParam(required = false) SessionStatus status) {
        return adminService.listUserSessions(userId, new SessionFilter(status), limit, offset);
    }

    @GetMapping("/audit-events")
    public List<AuditEventResponse> listAuditEvents(@RequestParam(defaultValue = "50") int limit,
                                                    @RequestParam(defaultValue = "0") int offset,
                                                    @RequestParam(required = false) AuditEventType eventType,
                                                    @RequestParam(required = false) UUID userId,
                                                    @RequestParam(required = false) UUID actorUserId,
                                                    @RequestParam(required = false) UUID targetUserId,
                                                    @RequestParam(required = false) String username,
                                                    @RequestParam(required = false) String sessionId,
                                                    @RequestParam(required = false) String ip,
                                                    @RequestParam(required = false)
                                                    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                                                    @RequestParam(required = false)
                                                    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        AuditEventFilter filter = new AuditEventFilter(
                eventType,
                userId,
                actorUserId,
                targetUserId,
                username,
                sessionId,
                ip,
                from,
                to
        );
        return adminService.listAuditEvents(filter, limit, offset);
    }

    @GetMapping("/auth-clients")
    public List<AuthClientResponse> listAuthClients() {
        return authClientService.listClients();
    }

    @GetMapping("/auth-clients/{clientId}")
    public AuthClientResponse getAuthClient(@PathVariable String clientId) {
        return authClientService.getClient(clientId);
    }

    @PostMapping("/auth-clients")
    public AuthClientResponse createAuthClient(@AuthenticationPrincipal Jwt jwt,
                                               @Valid @RequestBody AuthClientCreateRequest request) {
        return authClientService.createClient(JwtClaims.userId(jwt), request);
    }

    @PutMapping("/auth-clients/{clientId}")
    public AuthClientResponse updateAuthClient(@AuthenticationPrincipal Jwt jwt,
                                               @PathVariable String clientId,
                                               @Valid @RequestBody AuthClientUpdateRequest request) {
        return authClientService.updateClient(JwtClaims.userId(jwt), clientId, request);
    }

    @PostMapping("/auth-clients/{clientId}/enable")
    public AuthClientResponse enableAuthClient(@AuthenticationPrincipal Jwt jwt,
                                               @PathVariable String clientId) {
        return authClientService.enableClient(JwtClaims.userId(jwt), clientId);
    }

    @PostMapping("/auth-clients/{clientId}/disable")
    public AuthClientResponse disableAuthClient(@AuthenticationPrincipal Jwt jwt,
                                                @PathVariable String clientId) {
        return authClientService.disableClient(JwtClaims.userId(jwt), clientId);
    }

    @PostMapping("/users/{userId}/logout-all")
    public ResponseEntity<Void> logoutUserEverywhere(@AuthenticationPrincipal Jwt jwt,
                                                     @PathVariable UUID userId) {
        adminService.logoutUserEverywhere(JwtClaims.userId(jwt), userId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/users/{userId}/sessions/{sessionId}/revoke")
    public ResponseEntity<Void> revokeUserSession(@AuthenticationPrincipal Jwt jwt,
                                                  @PathVariable UUID userId,
                                                  @PathVariable String sessionId) {
        adminService.revokeUserSession(JwtClaims.userId(jwt), userId, sessionId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/users/{userId}/ban")
    public AdminUserResponse banUser(@AuthenticationPrincipal Jwt jwt,
                                     @PathVariable UUID userId,
                                     @Valid @RequestBody UserBanRequest request) {
        return adminService.banUser(JwtClaims.userId(jwt), userId, request.expiresAt(), request.reason());
    }

    @DeleteMapping("/users/{userId}/ban")
    public AdminUserResponse unbanUser(@AuthenticationPrincipal Jwt jwt,
                                       @PathVariable UUID userId) {
        return adminService.unbanUser(JwtClaims.userId(jwt), userId);
    }

    @PutMapping("/users/{userId}/roles/admin")
    public ResponseEntity<Void> grantAdmin(@AuthenticationPrincipal Jwt jwt,
                                           @PathVariable UUID userId) {
        adminService.grantAdmin(JwtClaims.userId(jwt), userId);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/users/{userId}/roles/admin")
    public ResponseEntity<Void> revokeAdmin(@AuthenticationPrincipal Jwt jwt,
                                            @PathVariable UUID userId) {
        adminService.revokeAdmin(JwtClaims.userId(jwt), userId);
        return ResponseEntity.noContent().build();
    }
}
