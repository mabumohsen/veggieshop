package io.veggieshop.platform.starter.application.autoconfig;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Cryptographic keys used by the application.
 *
 * <p>Prefix: {@code veggieshop.crypto.keys}.
 */
@ConfigurationProperties(prefix = "veggieshop.crypto.keys")
@Validated
public class CryptoKeysProperties {

  /** AEAD key material for development (disable or override in production). */
  private Key aead = new Key();

  /** HMAC key material for development (disable or override in production). */
  private Key hmac = new Key();

  /**
   * Holder for a single logical key. Contains a key identifier and Base64-encoded secret material.
   */
  public static class Key {
    @NotBlank private String kid = "dev-1";

    /** Base64 secret material (e.g., 32 bytes for AES-256 or HMAC-SHA256). */
    @NotBlank private String secretBase64 = "REPLACE_WITH_BASE64_SECRET";

    /** No-args constructor. */
    public Key() {}

    /** Copy constructor for defensive copies. */
    public Key(Key other) {
      if (other != null) {
        this.kid = other.kid;
        this.secretBase64 = other.secretBase64;
      }
    }

    public String getKid() {
      return kid;
    }

    public void setKid(String kid) {
      this.kid = kid;
    }

    public String getSecretBase64() {
      return secretBase64;
    }

    public void setSecretBase64(String secretBase64) {
      this.secretBase64 = secretBase64;
    }
  }

  /** Returns a defensive copy of the AEAD key. */
  public Key getAead() {
    return new Key(aead);
  }

  /** Stores a defensive copy of the AEAD key. */
  public void setAead(Key aead) {
    this.aead = (aead == null) ? new Key() : new Key(aead);
  }

  /** Returns a defensive copy of the HMAC key. */
  public Key getHmac() {
    return new Key(hmac);
  }

  /** Stores a defensive copy of the HMAC key. */
  public void setHmac(Key hmac) {
    this.hmac = (hmac == null) ? new Key() : new Key(hmac);
  }
}
