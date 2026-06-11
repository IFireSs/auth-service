package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

@Component
public class RateLimitAccountKeyHasher {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecretKeySpec secretKey;

    public RateLimitAccountKeyHasher(RateLimitProperties properties) {
        this.secretKey = new SecretKeySpec(
                properties.login().accountKeySecret().getBytes(StandardCharsets.UTF_8),
                HMAC_ALGORITHM
        );
    }

    public String hash(String normalizedAccountIdentifier) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKey);
            return HexFormat.of().formatHex(mac.doFinal(normalizedAccountIdentifier.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create rate limit account key", e);
        }
    }
}
