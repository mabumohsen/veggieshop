package io.veggieshop.platform.application.crypto;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

public final class KeyMetadata {
    private final String keyId;
    private final CryptoKeyUse use;
    private final Instant createdAt;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String fingerprint;

    public KeyMetadata(String keyId,
                       CryptoKeyUse use,
                       Instant createdAt,
                       Instant notBefore,
                       Instant notAfter,
                       byte[] publicDigest) {
        this.keyId = Objects.requireNonNull(keyId);
        this.use = Objects.requireNonNull(use);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.notBefore = Objects.requireNonNull(notBefore);
        this.notAfter = Objects.requireNonNull(notAfter);
        this.fingerprint = "sha256:" + HexFormat.of().formatHex(publicDigest == null ? new byte[0] : publicDigest);
    }

    public String getKeyId() { return keyId; }
    public CryptoKeyUse getUse() { return use; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getNotBefore() { return notBefore; }
    public Instant getNotAfter() { return notAfter; }
    public String getFingerprint() { return fingerprint; }
}
