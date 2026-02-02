package com.project.budget_manager.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class SecureController {
    @GetMapping("/api/v1/secure/role-test")
    public ResponseEntity<?> oke(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of("roles", jwt.getClaim("roles")));
    }
}
