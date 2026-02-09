package com.project.budget_manager.security.service;

import com.project.budget_manager.security.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AccessTokenService {
    private final JwtEncoder jwtEncoder;

    public String issueAccessToken(Long userId, String username, Collection<Role> roles, String sessionId) {

        Instant now = Instant.now();
        List<String> stringRoles = roles.stream()
                .map(Role::authority)
                .toList();

        var claims = JwtClaimsSet.builder()
                .issuer("budget-manager")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(username)
                .claim("uid", userId)
                .claim("roles", stringRoles)
                .claim("sid", sessionId)
                .build();

        var headers = JwsHeader.with(MacAlgorithm.HS256).build();

        return jwtEncoder.encode(JwtEncoderParameters.from(headers, claims)).getTokenValue();
    }
}
