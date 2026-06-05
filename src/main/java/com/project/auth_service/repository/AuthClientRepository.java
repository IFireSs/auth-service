package com.project.auth_service.repository;

import com.project.auth_service.entity.AuthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthClientRepository extends JpaRepository<AuthClient, Long> {
    Optional<AuthClient> findByClientId(String clientId);

    Optional<AuthClient> findByClientIdAndEnabledTrue(String clientId);

    List<AuthClient> findByEnabledTrue();

    boolean existsByClientId(String clientId);

    boolean existsByClientIdAndEnabledTrue(String clientId);
}
