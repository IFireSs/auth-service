package com.project.budget_manager.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;

@Service
@RequiredArgsConstructor
public class AccessTokenService {
    private final JwtEncoder jwtEncoder;

    public String issueAccessToken(Long userId, String username, Collection<String> roles) {

        Instant now = Instant.now();

        var claims = JwtClaimsSet.builder()
                .issuer("budget-manager")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(username)
                .claim("uid", userId)
                .claim("roles", roles)
                .build();

        var headers = JwsHeader.with(MacAlgorithm.HS256).build();

        return jwtEncoder.encode(JwtEncoderParameters.from(headers, claims)).getTokenValue();
    }
}
