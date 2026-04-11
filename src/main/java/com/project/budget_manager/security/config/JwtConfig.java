package com.project.budget_manager.security.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.project.budget_manager.security.service.AccessTokenStateValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
public class JwtConfig {

    @Bean
    public SecretKey jwtSecretKey(AppSecurityProperties securityProperties) {
        return new SecretKeySpec(securityProperties.jwt().secret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey secretKey){
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(SecretKey secretKey,
                                 AccessTokenStateValidator accessTokenStateValidator,
                                 AppSecurityProperties securityProperties){
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(securityProperties.accessToken().issuer()),
                accessTokenStateValidator
        ));
        return decoder;
    }
}
