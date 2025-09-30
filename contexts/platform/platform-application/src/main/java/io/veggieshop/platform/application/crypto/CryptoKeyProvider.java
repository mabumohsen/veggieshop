package io.veggieshop.platform.application.crypto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Optional;
import javax.crypto.SecretKey;

/**
 * CryptoKeyProvider
 *
 * <p>Abstraction for resolving cryptographic keys by intended use and key id. Implementations may
 * back keys by an HSM, KMS, or in-memory test store. Methods are expected to be thread-safe.
 */
public interface CryptoKeyProvider {

  /**
   * Returns the current (active) key id for the given use, to be used when creating new material.
   *
   * @param use the key use (e.g., AEAD or HMAC)
   * @return a non-blank key id
   */
  @NotBlank
  String currentKeyId(@NotNull CryptoKeyUse use);

  /**
   * Resolves a concrete key for the given key id and use.
   *
   * @param keyId a non-blank key identifier
   * @param use the intended key use
   * @return a non-null {@link SecretKey}
   * @throws IllegalArgumentException if the key cannot be found or the use is incompatible
   */
  @NotNull
  SecretKey resolveKey(@NotBlank String keyId, @NotNull CryptoKeyUse use);

  /**
   * Optional metadata for a key (algorithm, creation/rotation hints, etc.).
   *
   * @param keyId key identifier
   * @param use intended use
   * @return optional metadata if available
   */
  default Optional<KeyMetadata> metadata(String keyId, CryptoKeyUse use) {
    return Optional.empty();
  }
}
