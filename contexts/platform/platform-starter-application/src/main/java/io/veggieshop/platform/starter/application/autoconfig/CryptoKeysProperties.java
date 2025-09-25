package io.veggieshop.platform.starter.application.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;

@ConfigurationProperties(prefix = "veggieshop.crypto.keys")
@Validated
public class CryptoKeysProperties {
    /** مفاتيح AEAD للتطوير (يمكن تعطيلها في الإنتاج) */
    private Key aead = new Key();
    /** مفاتيح HMAC للتطوير (يمكن تعطيلها في الإنتاج) */
    private Key hmac = new Key();

    public static class Key {
        @NotBlank private String kid = "dev-1";
        /** مادة المفتاح Base64 (32 bytes لـ AES-256 أو 32 bytes لـ HMAC-SHA256). */
        @NotBlank private String secretBase64 = "uWk1t9l1m3Z1y7...ضع_سراً_هنا...";
        public String getKid() { return kid; }
        public void setKid(String kid) { this.kid = kid; }
        public String getSecretBase64() { return secretBase64; }
        public void setSecretBase64(String secretBase64) { this.secretBase64 = secretBase64; }
    }

    public Key getAead() { return aead; }
    public void setAead(Key aead) { this.aead = aead; }
    public Key getHmac() { return hmac; }
    public void setHmac(Key hmac) { this.hmac = hmac; }
}
