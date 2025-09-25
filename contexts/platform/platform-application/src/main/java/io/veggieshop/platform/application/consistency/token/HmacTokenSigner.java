package io.veggieshop.platform.application.consistency.token;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/**
 * HmacTokenSigner
 *
 * Thread-safe HMAC signer/verifier with key rotation support.
 * - Algorithm: HmacSHA256 (default/fixed here)
 * - Keys: map of keyId -> secret bytes
 * - Active key: used for new tokens; old keys remain for verification
 */
public final class HmacTokenSigner implements TokenSigner {

    public static final String DEFAULT_ALGORITHM = "HmacSHA256";

    private final String algorithm;
    private final String activeKeyId;
    private final Map<String, byte[]> secretsByKeyId;

    /**
     * @param activeKeyId      the key id used for new signatures
     * @param secretsByKeyId   map of key id -> secret key bytes (must include activeKeyId)
     * @param algorithm        HMAC algorithm (e.g., "HmacSHA256"); if null uses default
     */
    public HmacTokenSigner(String activeKeyId,
                           Map<String, byte[]> secretsByKeyId,
                           String algorithm) {
        TokenSigner.requireNotBlank(activeKeyId, "activeKeyId");
        Objects.requireNonNull(secretsByKeyId, "secretsByKeyId");
        if (!secretsByKeyId.containsKey(activeKeyId)) {
            throw new IllegalArgumentException("secretsByKeyId must contain activeKeyId");
        }
        this.activeKeyId = activeKeyId;
        this.secretsByKeyId = Map.copyOf(secretsByKeyId);
        this.algorithm = (algorithm == null || algorithm.isBlank())
                ? DEFAULT_ALGORITHM : algorithm.trim();
    }

    public HmacTokenSigner(String activeKeyId, Map<String, byte[]> secretsByKeyId) {
        this(activeKeyId, secretsByKeyId, DEFAULT_ALGORITHM);
    }

    @Override
    public String algorithm() {
        return algorithm;
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }

    @Override
    public byte[] sign(String keyId, byte[] bytes) {
        TokenSigner.requireNotBlank(keyId, "keyId");
        Objects.requireNonNull(bytes, "bytes");
        byte[] secret = secretsByKeyId.get(keyId);
        if (secret == null) {
            throw new IllegalArgumentException("Unknown keyId: " + keyId);
        }
        return hmac(secret, bytes);
    }

    @Override
    public boolean verify(String keyId, byte[] bytes, byte[] signature) {
        TokenSigner.requireNotBlank(keyId, "keyId");
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(signature, "signature");
        byte[] secret = secretsByKeyId.get(keyId);
        if (secret == null) return false;
        byte[] expected = hmac(secret, bytes);
        return constantTimeEquals(expected, signature);
    }

    // -------------- Crypto primitives --------------

    private byte[] hmac(byte[] secret, byte[] bytes) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret, algorithm));
            return mac.doFinal(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC failure (" + algorithm + ")", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        // Prefer JDK's constant-time comparison
        return MessageDigest.isEqual(
                (a == null ? new byte[0] : a),
                (b == null ? new byte[0] : b)
        );
    }

    @Override
    public String toString() {
        return "HmacTokenSigner{alg=" + algorithm + ", activeKeyId='" + activeKeyId
                + "', keys=" + secretsByKeyId.keySet() + "}";
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, activeKeyId, secretsByKeyId.keySet());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof HmacTokenSigner other)) return false;
        return Objects.equals(this.algorithm, other.algorithm)
                && Objects.equals(this.activeKeyId, other.activeKeyId)
                // keys compared by id set only (not by secret bytes)
                && Objects.equals(this.secretsByKeyId.keySet(), other.secretsByKeyId.keySet());
    }
}
