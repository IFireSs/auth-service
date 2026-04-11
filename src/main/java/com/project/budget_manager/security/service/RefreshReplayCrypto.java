package com.project.budget_manager.security.service;

import com.nimbusds.jose.util.Base64URL;
import com.project.budget_manager.security.config.AppSecurityProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class RefreshReplayCrypto {
    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_LENGTH = 12;

    private final SecureRandom secureRandom = new SecureRandom();
    private final SecretKeySpec aesKey;

    public RefreshReplayCrypto(AppSecurityProperties securityProperties) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(securityProperties.jwt().secret().getBytes(StandardCharsets.UTF_8));
            this.aesKey = new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Unable to derive refresh replay key", e);
        }
    }

    public String encrypt(String rawToken) {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(rawToken.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, payload, 0, nonce.length);
            System.arraycopy(ciphertext, 0, payload, nonce.length, ciphertext.length);

            return Base64URL.encode(payload).toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to encrypt refresh replay payload", e);
        }
    }

    public String decrypt(String cipherText) {
        try {
            byte[] payload = Base64URL.from(cipherText).decode();
            byte[] nonce = Arrays.copyOfRange(payload, 0, NONCE_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(payload, NONCE_LENGTH, payload.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] clear = cipher.doFinal(ciphertext);
            return new String(clear, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to decrypt refresh replay payload", e);
        }
    }
}
