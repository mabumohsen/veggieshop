package io.veggieshop.platform.starter.data.autoconfig;

import io.veggieshop.platform.infrastructure.pii.PiiVaultJdbcAdapter.PiiVaultConfig;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.lang.Nullable;

/**
 * Properties: veggieshop.pii.vault.active-kid: k1 veggieshop.pii.vault.master-keys.k1: "Base64(32
 * bytes)" veggieshop.pii.vault.default-ttl: 365d veggieshop.pii.vault.max-payload-bytes: 16384
 * veggieshop.pii.vault.salt-bytes: 16 veggieshop.pii.vault.iv-bytes: 12
 * veggieshop.pii.vault.fail-if-missing-key: true
 */
@ConfigurationProperties(prefix = "veggieshop.pii.vault")
public class VeggiePiiVaultProperties implements PiiVaultConfig {

  private String activeKid = "k1";
  private Map<String, String> masterKeys = new HashMap<>();
  @Nullable private Duration defaultTtl = Duration.ofDays(365);
  private int maxPayloadBytes = 16 * 1024;
  private int saltBytes = 16;
  private int ivBytes = 12;
  private boolean failIfMissingKey = true;

  // getters/setters
  @Override
  public String getActiveKid() {
    return activeKid;
  }

  public void setActiveKid(String activeKid) {
    this.activeKid = activeKid;
  }

  @Override
  public Map<String, String> getMasterKeys() {
    // Defensive: do not expose internal map
    return Collections.unmodifiableMap(masterKeys);
  }

  public void setMasterKeys(Map<String, String> masterKeys) {
    // Defensive copy: do not store caller's mutable reference
    this.masterKeys = (masterKeys == null) ? new HashMap<>() : new HashMap<>(masterKeys);
  }

  @Override
  public @Nullable Duration getDefaultTtl() {
    return defaultTtl;
  }

  public void setDefaultTtl(@Nullable Duration defaultTtl) {
    this.defaultTtl = defaultTtl;
  }

  @Override
  public int getMaxPayloadBytes() {
    return maxPayloadBytes;
  }

  public void setMaxPayloadBytes(int maxPayloadBytes) {
    this.maxPayloadBytes = maxPayloadBytes;
  }

  @Override
  public int getSaltBytes() {
    return saltBytes;
  }

  public void setSaltBytes(int saltBytes) {
    this.saltBytes = saltBytes;
  }

  @Override
  public int getIvBytes() {
    return ivBytes;
  }

  public void setIvBytes(int ivBytes) {
    this.ivBytes = ivBytes;
  }

  @Override
  public boolean isFailIfMissingKey() {
    return failIfMissingKey;
  }

  public void setFailIfMissingKey(boolean failIfMissingKey) {
    this.failIfMissingKey = failIfMissingKey;
  }

  @Override
  public @Nullable byte[] masterKeyBytes(String kid) {
    String b64 = masterKeys.get(kid);
    // Base64.decode returns a fresh array; no additional copy needed.
    return (b64 != null) ? Base64.getDecoder().decode(b64) : null;
  }
}
