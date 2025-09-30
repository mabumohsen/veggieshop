package io.veggieshop.platform.application.crypto;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * KeyMetadata
 *
 * <p>Immutable metadata describing a cryptographic key: identifier, intended use, creation time,
 * validity window, and a SHA-256 fingerprint of the public material (if provided).
 */
public final class KeyMetadata {
  private final String keyId;
  private final CryptoKeyUse use;
  private final Instant createdAt;
  private final Instant notBefore;
  private final Instant notAfter;
  private final String fingerprint;

  /**
   * Creates a new {@code KeyMetadata}.
   *
   * @param keyId unique key identifier (non-null)
   * @param use intended cryptographic use (e.g., AEAD, HMAC)
   * @param createdAt key creation instant
   * @param notBefore earliest instant at which the key is valid
   * @param notAfter latest instant after which the key is no longer valid
   * @param publicDigest SHA-256 digest of the public material (may be {@code null}); if null, the
   *     fingerprint is computed over an empty byte array
   */
  public KeyMetadata(
      String keyId,
      CryptoKeyUse use,
      Instant createdAt,
      Instant notBefore,
      Instant notAfter,
      byte[] publicDigest) {
    this.keyId = Objects.requireNonNull(keyId, "keyId");
    this.use = Objects.requireNonNull(use, "use");
    this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
    this.notBefore = Objects.requireNonNull(notBefore, "notBefore");
    this.notAfter = Objects.requireNonNull(notAfter, "notAfter");
    this.fingerprint =
        "sha256:" + HexFormat.of().formatHex(publicDigest == null ? new byte[0] : publicDigest);
  }

  /**
   * Returns the unique key identifier.
   *
   * @return the unique key identifier
   */
  public String getKeyId() {
    return keyId;
  }

  /**
   * Returns the intended cryptographic use.
   *
   * @return the intended cryptographic use
   */
  public CryptoKeyUse getUse() {
    return use;
  }

  /**
   * Returns the key creation instant.
   *
   * @return the key creation instant
   */
  public Instant getCreatedAt() {
    return createdAt;
  }

  /**
   * Returns the earliest instant at which the key is valid.
   *
   * @return the earliest valid instant
   */
  public Instant getNotBefore() {
    return notBefore;
  }

  /**
   * Returns the latest instant after which the key is no longer valid.
   *
   * @return the latest valid instant
   */
  public Instant getNotAfter() {
    return notAfter;
  }

  /**
   * Returns the SHA-256 fingerprint string.
   *
   * @return fingerprint in the form {@code sha256:<hex>}
   */
  public String getFingerprint() {
    return fingerprint;
  }
}
