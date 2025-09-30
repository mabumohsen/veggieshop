package io.veggieshop.platform.starter.application.autoconfig;

import io.veggieshop.platform.infrastructure.pii.PiiVaultJdbcAdapter.PiiVaultConfig;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the PII Vault JDBC adapter. Prefix: {@code veggieshop.pii.vault}.
 */
@ConfigurationProperties(prefix = "veggieshop.pii.vault")
public class VeggiePiiVaultProperties implements PiiVaultConfig {

  private String activeKid = "k1";

  /** Map of key-id to key material (Base64 or Hex). */
  private Map<String, String> masterKeys = Map.of();

  /** Default time-to-live for stored payloads. Zero means "no TTL". */
  private Duration defaultTtl = Duration.ZERO;

  private int maxPayloadBytes = 64 * 1024;
  private int saltBytes = 16;
  private int ivBytes = 12;
  private boolean failIfMissingKey = true;

  /** Encoding of key material in {@code masterKeys}: either {@code base64} or {@code hex}. */
  private String encoding = "base64";

  // ---------------- Getters required by PiiVaultConfig ----------------

  @Override
  public String getActiveKid() {
    return activeKid;
  }

  @Override
  public Map<String, String> getMasterKeys() {
    // Defensive copy to avoid exposing internal representation.
    return Map.copyOf(masterKeys);
  }

  @Override
  public Duration getDefaultTtl() {
    return defaultTtl;
  }

  @Override
  public int getMaxPayloadBytes() {
    return maxPayloadBytes;
  }

  @Override
  public int getSaltBytes() {
    return saltBytes;
  }

  @Override
  public int getIvBytes() {
    return ivBytes;
  }

  @Override
  public boolean isFailIfMissingKey() {
    return failIfMissingKey;
  }

  @Override
  public byte[] masterKeyBytes(String kid) {
    if (kid == null || masterKeys == null) {
      return null;
    }
    String raw = masterKeys.get(kid);
    if (raw == null) {
      return null;
    }
    try {
      return "hex".equalsIgnoreCase(encoding) ? hex(raw) : Base64.getDecoder().decode(raw);
    } catch (IllegalArgumentException ex) {
      // Invalid key encoding.
      return null;
    }
  }

  // ---------------- Standard setters for property binding ----------------

  public void setActiveKid(String activeKid) {
    this.activeKid = activeKid;
  }

  public void setMasterKeys(Map<String, String> masterKeys) {
    this.masterKeys = (masterKeys == null) ? Map.of() : Map.copyOf(masterKeys);
  }

  public void setDefaultTtl(Duration defaultTtl) {
    this.defaultTtl = (defaultTtl == null) ? Duration.ZERO : defaultTtl;
  }

  public void setMaxPayloadBytes(int maxPayloadBytes) {
    this.maxPayloadBytes = maxPayloadBytes;
  }

  public void setSaltBytes(int saltBytes) {
    this.saltBytes = saltBytes;
  }

  public void setIvBytes(int ivBytes) {
    this.ivBytes = ivBytes;
  }

  public void setFailIfMissingKey(boolean failIfMissingKey) {
    this.failIfMissingKey = failIfMissingKey;
  }

  public String getEncoding() {
    return encoding;
  }

  public void setEncoding(String encoding) {
    this.encoding = (encoding == null) ? "base64" : encoding;
  }

  // ---------------- Helpers ----------------

  private static byte[] hex(String s) {
    int len = s.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] =
          (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }
    return out;
  }
}
