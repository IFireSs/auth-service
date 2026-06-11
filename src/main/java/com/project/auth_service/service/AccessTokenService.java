package com.project.auth_service.service;

import com.project.auth_service.config.AppSecurityProperties;
import com.project.auth_service.entity.AuthClient;
import com.project.auth_service.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class AccessTokenService {
    private final JwtEncoder jwtEncoder;
    private final AppSecurityProperties securityProperties;
    private final AuthClientService authClientService;

    public String issueAccessToken(UUID userId,
                                   String username,
                                   Collection<Role> roles,
                                   String sessionId,
                                   AuthClient client) {

        Instant now = Instant.now();
        List<String> stringRoles = roles.stream()
                .map(Role::name)
                .toList();
        List<String> audiences = Stream.of(
                        securityProperties.accessToken().audience(),
                        client.getTokenAudience()
                )
                .distinct()
                .toList();

        var claims = JwtClaimsSet.builder()
                .issuer(securityProperties.accessToken().issuer())
                .issuedAt(now)
                .expiresAt(now.plus(effectiveAccessTokenTtl(client)))
                .subject(username)
                .audience(audiences)
                .claim(JwtClaims.USER_ID, userId.toString())
                .claim(JwtClaims.ROLES, stringRoles)
                .claim(JwtClaims.SESSION_ID, sessionId)
                .claim(JwtClaims.CLIENT_ID, client.getClientId())
                .build();

        var headers = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(securityProperties.jwt().keyId())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(headers, claims)).getTokenValue();
    }

    private Duration effectiveAccessTokenTtl(AuthClient client) {
        Duration clientTtl = authClientService.accessTokenTtl(client);
        Duration globalTtl = securityProperties.accessToken().ttl();
        return clientTtl.compareTo(globalTtl) <= 0 ? clientTtl : globalTtl;
    }
}
