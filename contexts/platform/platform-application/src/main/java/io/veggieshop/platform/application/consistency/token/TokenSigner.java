package io.veggieshop.platform.application.consistency.token;

import java.util.Objects;

/**
 * TokenSigner
 *
 * A minimal signing interface to support key rotation and algorithm abstraction.
 * Implementations must be thread-safe.
 */
public interface TokenSigner {

    /**
     * @return algorithm identifier (e.g., "HmacSHA256")
     */
    String algorithm();

    /**
     * @return active key id used when encoding new tokens (non-empty).
     */
    String activeKeyId();

    /**
     * Produce a signature over the provided bytes using the key identified by {@code keyId}.
     */
    byte[] sign(String keyId, byte[] bytes);

    /**
     * Verify the signature using the key identified by {@code keyId}.
     */
    boolean verify(String keyId, byte[] bytes, byte[] signature);

    // -------------- Small helper --------------

    /**
     * Convenience precondition.
     */
    static void requireNotBlank(String s, String name) {
        if (s == null || s.isBlank()) {
            throw new IllegalArgumentException(name + " must be non-empty");
        }
    }

    /**
     * Defensive clone for signature byte[].
     */
    static byte[] copy(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return bytes.clone();
    }
}
