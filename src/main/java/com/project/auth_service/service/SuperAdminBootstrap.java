package com.project.auth_service.service;

import com.project.auth_service.config.SuperAdminBootstrapProperties;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.enums.Role;
import com.project.auth_service.repository.UserRepository;
import com.project.auth_service.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class SuperAdminBootstrap implements ApplicationRunner {
    private final SuperAdminBootstrapProperties properties;
    private final AuthUserService authUserService;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditEventService auditEventService;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.enabled()) {
            return;
        }

        long superAdminCount = userRoleRepository.countByRole(Role.SUPER_ADMIN);
        if (superAdminCount > 0) {
            log.info("Super admin bootstrap is enabled, but a SUPER_ADMIN already exists. Skipping bootstrap.");
            return;
        }

        validateProperties();
        validateBootstrapAllowed();

        var superAdmin = authUserService.registerLocalUser(
                properties.username(),
                properties.email(),
                passwordEncoder.encode(properties.password()),
                List.of(Role.SUPER_ADMIN)
        );
        userRepository.findById(superAdmin.id()).orElseThrow().setBanProtected(true);

        auditEventService.record(AuditEventType.SUPER_ADMIN_BOOTSTRAPPED, AuditEventService.AuditEventCommand.builder()
                .targetUserId(superAdmin.id())
                .username(superAdmin.username())
                .details(Map.of("role", Role.SUPER_ADMIN.name()))
                .build());

        log.warn("Bootstrapped initial SUPER_ADMIN user '{}'. Disable app.bootstrap.super-admin.enabled after first startup.",
                superAdmin.username());
    }

    private void validateProperties() {
        if (isBlank(properties.username()) || isBlank(properties.email()) || isBlank(properties.password())) {
            throw new IllegalStateException("Super admin bootstrap is enabled, but username, email or password is blank");
        }
        if ("change-me".equals(properties.password())) {
            throw new IllegalStateException("Super admin bootstrap password must be changed from the default placeholder");
        }
        if (properties.password().length() < 12) {
            throw new IllegalStateException("Super admin bootstrap password must be at least 12 characters long");
        }
    }

    private void validateBootstrapAllowed() {
        if (properties.requireEmptyUserStore() && userRepository.count() > 0) {
            throw new IllegalStateException("""
                    Super admin bootstrap is enabled, but users already exist and no SUPER_ADMIN role was found.
                    Refusing to create a privileged user in a non-empty user store.
                    Disable require-empty-user-store only for an intentional recovery procedure.
                    """);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
