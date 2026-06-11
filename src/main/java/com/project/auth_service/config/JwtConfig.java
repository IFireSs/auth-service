package com.project.auth_service.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.project.auth_service.service.AccessTokenAudienceValidator;
import com.project.auth_service.service.AccessTokenStateValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    @Bean
    public RSAKey jwtRsaKey(AppSecurityProperties securityProperties) {
        RSAPublicKey publicKey = parsePublicKey(securityProperties.jwt().publicKey());
        RSAPrivateKey privateKey = parsePrivateKey(securityProperties.jwt().privateKey());

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(securityProperties.jwt().keyId())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey jwtRsaKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwtRsaKey)));
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey jwtRsaKey,
                                 AccessTokenAudienceValidator accessTokenAudienceValidator,
                                 AccessTokenStateValidator accessTokenStateValidator,
                                 AppSecurityProperties securityProperties) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtRsaKey.toRSAPublicKey()).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(securityProperties.accessToken().issuer()),
                accessTokenAudienceValidator,
                accessTokenStateValidator
        ));
        return decoder;
    }

    private RSAPrivateKey parsePrivateKey(String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(normalizeKey(key));
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to parse JWT RSA private key", e);
        }
    }

    private RSAPublicKey parsePublicKey(String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(normalizeKey(key));
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to parse JWT RSA public key", e);
        }
    }

    private String normalizeKey(String key) {
        return key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\n", "")
                .replace("\\r", "")
                .replaceAll("\\s", "");
    }
}
