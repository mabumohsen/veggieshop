package io.veggieshop.platform.application.consistency.token;

import java.util.Objects;

/**
 * TokenSigner
 *
 * <p>A minimal signing interface to support key rotation and algorithm abstraction. Implementations
 * must be thread-safe.
 */
public interface TokenSigner {

  /**
   * Returns the algorithm identifier used for signatures (e.g., "HmacSHA256").
   *
   * @return algorithm identifier.
   */
  String algorithm();

  /**
   * Returns the active key id that should be used when encoding new tokens.
   *
   * @return non-empty active key id.
   */
  String activeKeyId();

  /** Produce a signature over the provided bytes using the key identified by {@code keyId}. */
  byte[] sign(String keyId, byte[] bytes);

  /** Verify the signature using the key identified by {@code keyId}. */
  boolean verify(String keyId, byte[] bytes, byte[] signature);

  // -------------- Small helper --------------

  /** Convenience precondition that asserts a string is non-null and non-blank. */
  static void requireNotBlank(String s, String name) {
    if (s == null || s.isBlank()) {
      throw new IllegalArgumentException(name + " must be non-empty");
    }
  }

  /** Defensive clone for a signature or message byte array. */
  static byte[] copy(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    return bytes.clone();
  }
}
