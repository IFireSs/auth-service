package com.project.auth_service.api;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
@RequiredArgsConstructor
public class JwksController {
    private final RSAKey jwtRsaKey;

    @GetMapping("/jwks.json")
    public Map<String, Object> getJwks() {
        return new JWKSet(jwtRsaKey.toPublicJWK()).toJSONObject();
    }
}
