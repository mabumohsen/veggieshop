package io.veggieshop.platform.application.crypto;

/**
 * CryptoKeyUse
 *
 * <p>Enumerates intended usages for cryptographic keys along with their algorithm family.
 */
public enum CryptoKeyUse {
  /** Authenticated encryption (e.g., AES-GCM). */
  AEAD("AES"),
  /** Message authentication (e.g., HmacSHA256). */
  HMAC("HmacSHA256");

  private final String algorithmFamily;

  CryptoKeyUse(String family) {
    this.algorithmFamily = family;
  }

  /**
   * Returns the algorithm family string associated with this use (for display/hinting only).
   *
   * @return algorithm family (e.g., "AES", "HmacSHA256")
   */
  public String algorithmFamily() {
    return algorithmFamily;
  }
}
