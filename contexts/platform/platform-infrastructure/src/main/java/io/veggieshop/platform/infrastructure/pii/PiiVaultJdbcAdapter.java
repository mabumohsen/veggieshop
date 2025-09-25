package io.veggieshop.platform.infrastructure.pii;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.veggieshop.platform.application.pii.PiiVaultClient;
import io.veggieshop.platform.application.pii.PiiVaultClient.PiiHandle;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * JDBC-backed PII vault adapter with envelope encryption and KID-based rotation.
 *
 * Schema (Flyway):
 * CREATE TABLE pii_vault (
 *   tenant_id    TEXT NOT NULL,
 *   pii_ref      UUID NOT NULL PRIMARY KEY,
 *   kid          TEXT NOT NULL,
 *   salt         BYTEA NOT NULL,
 *   iv           BYTEA NOT NULL,
 *   ciphertext   BYTEA NOT NULL,
 *   content_type TEXT,
 *   created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
 *   expires_at   TIMESTAMPTZ NULL,
 *   version      INT NOT NULL DEFAULT 1
 * );
 */
public class PiiVaultJdbcAdapter implements PiiVaultClient.PiiVaultPort {

    private static final Logger log = LoggerFactory.getLogger(PiiVaultJdbcAdapter.class);

    private static final String ALG_GCM = "AES/GCM/NoPadding";
    private static final String HKDF_HMAC = "HmacSHA256";
    private static final int GCM_TAG_BITS = 128;  // 16 bytes tag
    private static final int SALT_BYTES_DEFAULT = 16;
    private static final int IV_BYTES_DEFAULT = 12;

    private static final SecureRandom RNG = new SecureRandom();

    private final JdbcTemplate jdbc;
    private final PiiVaultConfig props;
    private final ObjectMapper json;
    @Nullable private final MeterRegistry meters;

    // Metrics (optional)
    @Nullable private final Counter mPutOk, mPutErr, mGetHit, mGetMiss, mDelOk, mDelErr, mRotateOk, mRotateErr;

    public PiiVaultJdbcAdapter(JdbcTemplate jdbc,
                               PiiVaultConfig props,
                               @Nullable MeterRegistry meterRegistry,
                               ObjectMapper json) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.props = Objects.requireNonNull(props, "props");
        this.meters = meterRegistry;
        this.json = Objects.requireNonNull(json, "json");

        if (meters != null) {
            mPutOk    = Counter.builder("pii.vault.put.ok").register(meters);
            mPutErr   = Counter.builder("pii.vault.put.err").register(meters);
            mGetHit   = Counter.builder("pii.vault.get.hit").register(meters);
            mGetMiss  = Counter.builder("pii.vault.get.miss").register(meters);
            mDelOk    = Counter.builder("pii.vault.delete.ok").register(meters);
            mDelErr   = Counter.builder("pii.vault.delete.err").register(meters);
            mRotateOk = Counter.builder("pii.vault.rotate.ok").register(meters);
            mRotateErr= Counter.builder("pii.vault.rotate.err").register(meters);
        } else {
            mPutOk = mPutErr = mGetHit = mGetMiss = mDelOk = mDelErr = mRotateOk = mRotateErr = null;
        }

        validateKeys();
    }

    // -------------------------------------------------------------------------------------
    // PiiVaultPort API
    // -------------------------------------------------------------------------------------

    @Override
    public PiiHandle upsert(@NotNull TenantId tenantId,
                            @NotBlank String subjectType,
                            @NotBlank String subjectId,
                            @NotNull Map<String, String> pii,
                            @Nullable Duration retention,
                            @Nullable Map<String, String> tags,
                            @Nullable String idempotencyKey) {
        final byte[] plaintext;
        try {
            plaintext = json.writeValueAsBytes(pii); // لا تسجّل محتوى PII
        } catch (Exception e) {
            throw new VaultPersistenceException("PII serialization failed", e);
        }

        final Instant now = Instant.now();
        final Instant expiresAt = (retention == null || retention.isZero() || retention.isNegative())
                ? null
                : now.plus(retention);

        final String ref = put(
                tenantId.value(),
                plaintext,
                "application/json; charset=utf-8; v=1",
                expiresAt
        );

        return currentHandle(tenantId, ref);
    }

    @Override
    public Optional<Map<String, String>> read(@NotNull TenantId tenantId, @NotBlank String ref) {
        Optional<byte[]> opt = get(tenantId.value(), ref);
        if (opt.isEmpty()) return Optional.empty();
        try {
            Map<String, String> map = json.readValue(opt.get(), new TypeReference<Map<String, String>>() {});
            return Optional.of(map);
        } catch (Exception e) {
            throw new VaultPersistenceException("PII deserialization failed", e);
        }
    }

    @Override
    public PiiHandle redactFields(@NotNull TenantId tenantId,
                                  @NotBlank String ref,
                                  @NotNull Set<String> fieldsToRemove) {
        if (fieldsToRemove.isEmpty()) {
            return currentHandle(tenantId, ref);
        }
        Map<String, String> current = read(tenantId, ref)
                .orElseThrow(() -> new VaultPersistenceException("PII ref not found or expired"));
        fieldsToRemove.forEach(current::remove);

        try {
            byte[] plaintext = json.writeValueAsBytes(current);
            // Re-encrypt under active KID with new salt/iv
            String kid = props.getActiveKid();
            byte[] master = masterKey(kid);
            byte[] newSalt = random(props.getSaltBytes());
            byte[] newIv = random(props.getIvBytes());
            byte[] aad = buildAad(tenantId.value(), ref, "application/json; charset=utf-8; v=1");
            byte[] newDek = hkdf(master, newSalt, aad, 32);
            byte[] newCipher = aesGcmEncrypt(newDek, newIv, aad, plaintext);
            Arrays.fill(newDek, (byte) 0);

            int rows = jdbc.update(
                    "UPDATE pii_vault SET kid=?, salt=?, iv=?, ciphertext=?, version=version+1 WHERE tenant_id=? AND pii_ref=?",
                    kid, newSalt, newIv, newCipher, tenantId.value(), java.util.UUID.fromString(ref)
            );
            if (rows != 1) throw new VaultPersistenceException("Failed to redact fields");

            return currentHandle(tenantId, ref);
        } catch (GeneralSecurityException e) {
            throw new VaultCryptoException("Redaction crypto failed", e);
        } catch (Exception e) {
            throw new VaultPersistenceException("Redaction failed", e);
        }
    }

    @Override
    public PiiHandle rotate(@NotNull TenantId tenantId, @NotBlank String ref) {
        boolean ok = rotate(tenantId.value(), ref, null);
        if (!ok) throw new VaultPersistenceException("Rotation failed");
        return currentHandle(tenantId, ref);
    }

    @Override
    public boolean delete(@NotNull TenantId tenantId, @NotBlank String ref, boolean hardDelete) {
        if (hardDelete) {
            return hardDeleteRow(tenantId.value(), ref);
        }
        // soft-delete via immediate expiry
        int rows = jdbc.update(
                "UPDATE pii_vault SET expires_at=? WHERE tenant_id=? AND pii_ref=?",
                java.util.Date.from(Instant.now()), tenantId.value(), java.util.UUID.fromString(ref)
        );
        return rows > 0;
    }

    @Override
    public PiiHandle currentHandle(@NotNull TenantId tenantId, @NotBlank String ref) {
        try {
            Number ver = jdbc.queryForObject(
                    "SELECT version FROM pii_vault WHERE tenant_id=? AND pii_ref=?",
                    Number.class, tenantId.value(), java.util.UUID.fromString(ref)
            );
            if (ver == null) throw new VaultPersistenceException("PII ref not found");
            return new PiiHandle(ref, ver.longValue());
        } catch (DataAccessException e) {
            throw new VaultPersistenceException("PII handle lookup failed", e);
        }
    }

    // -------------------------------------------------------------------------------------
    // Low-level blob ops
    // -------------------------------------------------------------------------------------

    private String put(String tenantId, byte[] plaintext, @Nullable String contentType, @Nullable Instant expiresAt) {
        requireTenant(tenantId);
        Objects.requireNonNull(plaintext, "plaintext");
        if (plaintext.length == 0) throw new IllegalArgumentException("plaintext must not be empty");
        if (plaintext.length > props.getMaxPayloadBytes()) {
            throw new IllegalArgumentException("payload too large (max " + props.getMaxPayloadBytes() + " bytes)");
        }
        String kid = props.getActiveKid();
        byte[] master = masterKey(kid);
        java.util.UUID piiRef = java.util.UUID.randomUUID();

        byte[] salt = random(props.getSaltBytes());
        byte[] iv = random(props.getIvBytes());
        byte[] aad = buildAad(tenantId, piiRef.toString(), contentType);

        byte[] ciphertext;
        try {
            byte[] dek = hkdf(master, salt, aad, 32); // 256-bit DEK
            ciphertext = aesGcmEncrypt(dek, iv, aad, plaintext);
            Arrays.fill(dek, (byte) 0);
        } catch (GeneralSecurityException e) {
            if (mPutErr != null) mPutErr.increment();
            throw new VaultCryptoException("Encryption failed", e);
        }

        Instant now = Instant.now();
        Instant exp = expiresAt;

        int rows = jdbc.update(
                "INSERT INTO pii_vault(tenant_id, pii_ref, kid, salt, iv, ciphertext, content_type, created_at, expires_at, version) " +
                        "VALUES (?,?,?,?,?,?,?,?,?,1)",
                tenantId, piiRef, kid, salt, iv, ciphertext, contentType, java.util.Date.from(now), exp != null ? java.util.Date.from(exp) : null
        );
        if (rows != 1) {
            if (mPutErr != null) mPutErr.increment();
            throw new VaultPersistenceException("Failed to insert PII record");
        }
        if (mPutOk != null) mPutOk.increment();
        log.debug("PII stored: piiRef={}, tenant={}", piiRef, tenantId);
        return piiRef.toString();
    }

    private Optional<byte[]> get(String tenantId, String piiRef) {
        requireTenant(tenantId);
        java.util.UUID ref = parseUuid(piiRef);

        try {
            Map<String, Object> row = jdbc.queryForMap(
                    "SELECT kid, salt, iv, ciphertext, content_type, expires_at FROM pii_vault WHERE tenant_id=? AND pii_ref=?",
                    tenantId, ref
            );
            TimestampLike expiresAt = TimestampLike.from(row.get("expires_at"));
            if (expiresAt.isExpired(Instant.now())) {
                if (mGetMiss != null) mGetMiss.increment();
                return Optional.empty();
            }

            String kid = (String) row.get("kid");
            byte[] salt = (byte[]) row.get("salt");
            byte[] iv = (byte[]) row.get("iv");
            byte[] ciphertext = (byte[]) row.get("ciphertext");
            String contentType = (String) row.get("content_type");

            byte[] aad = buildAad(tenantId, piiRef, contentType);
            byte[] master = masterKey(kid);
            byte[] plaintext;
            try {
                byte[] dek = hkdf(master, salt, aad, 32);
                plaintext = aesGcmDecrypt(dek, iv, aad, ciphertext);
                Arrays.fill(dek, (byte) 0);
            } catch (GeneralSecurityException e) {
                if (mGetMiss != null) mGetMiss.increment();
                throw new VaultCryptoException("Decryption failed", e);
            }
            if (mGetHit != null) mGetHit.increment();
            return Optional.of(plaintext);
        } catch (DataAccessException notFound) {
            if (mGetMiss != null) mGetMiss.increment();
            return Optional.empty();
        }
    }

    private boolean rotate(String tenantId, String piiRef, @Nullable String targetKid) {
        requireTenant(tenantId);
        java.util.UUID ref = parseUuid(piiRef);
        String newKid = targetKid != null ? targetKid : props.getActiveKid();
        byte[] newMaster = masterKey(newKid);

        try {
            Map<String, Object> row = jdbc.queryForMap(
                    "SELECT kid, salt, iv, ciphertext, content_type FROM pii_vault WHERE tenant_id=? AND pii_ref=?",
                    tenantId, ref
            );
            String curKid = (String) row.get("kid");
            if (Objects.equals(curKid, newKid)) {
                return true; // already under the target KID
            }
            byte[] salt = (byte[]) row.get("salt");
            byte[] iv = (byte[]) row.get("iv");
            byte[] ciphertext = (byte[]) row.get("ciphertext");
            String contentType = (String) row.get("content_type");

            byte[] aad = buildAad(tenantId, piiRef, contentType);

            byte[] curMaster = masterKey(curKid);
            byte[] dek = hkdf(curMaster, salt, aad, 32);
            byte[] plaintext = aesGcmDecrypt(dek, iv, aad, ciphertext);
            Arrays.fill(dek, (byte) 0);

            byte[] newSalt = random(props.getSaltBytes());
            byte[] newIv = random(props.getIvBytes());
            byte[] newDek = hkdf(newMaster, newSalt, aad, 32);
            byte[] newCipher = aesGcmEncrypt(newDek, newIv, aad, plaintext);
            Arrays.fill(newDek, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);

            int rows = jdbc.update(
                    "UPDATE pii_vault SET kid=?, salt=?, iv=?, ciphertext=?, version=version+1 WHERE tenant_id=? AND pii_ref=?",
                    newKid, newSalt, newIv, newCipher, tenantId, ref
            );
            if (rows == 1) {
                if (mRotateOk != null) mRotateOk.increment();
                log.info("PII rotated: piiRef={}, tenant={}, kid {} -> {}", piiRef, tenantId, curKid, newKid);
                return true;
            } else {
                if (mRotateErr != null) mRotateErr.increment();
                return false;
            }
        } catch (DataAccessException e) {
            if (mRotateErr != null) mRotateErr.increment();
            return false;
        } catch (GeneralSecurityException e) {
            if (mRotateErr != null) mRotateErr.increment();
            throw new VaultCryptoException("Rotation crypto failed", e);
        }
    }

    // -------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------

    private static void requireTenant(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
    }

    private static java.util.UUID parseUuid(String ref) {
        try {
            return java.util.UUID.fromString(ref);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid piiRef format");
        }
    }

    private byte[] masterKey(String kid) {
        byte[] k = props.masterKeyBytes(kid);
        if (k == null) {
            if (props.isFailIfMissingKey()) {
                throw new VaultConfigException("Missing master key for KID=" + kid);
            }
            // Fallback to active KID if allowed
            k = props.masterKeyBytes(props.getActiveKid());
            if (k == null) throw new VaultConfigException("Active master key is not configured");
        }
        return k;
    }

    private static byte[] buildAad(String tenantId, String piiRef, @Nullable String contentType) {
        // AAD layout: len|tenantId || len|piiRef || len|contentType
        byte[] t = tenantId.getBytes(StandardCharsets.UTF_8);
        byte[] r = piiRef.getBytes(StandardCharsets.UTF_8);
        byte[] c = contentType != null ? contentType.getBytes(StandardCharsets.UTF_8) : new byte[0];
        ByteBuffer bb = ByteBuffer.allocate(4 + t.length + 4 + r.length + 4 + c.length);
        bb.putInt(t.length).put(t);
        bb.putInt(r.length).put(r);
        bb.putInt(c.length).put(c);
        return bb.array();
    }

    private static byte[] random(int len) {
        byte[] out = new byte[len];
        RNG.nextBytes(out);
        return out;
    }

    private static byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALG_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALG_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    /** HKDF (RFC 5869) with HMAC-SHA-256. */
    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HKDF_HMAC);
        // Extract
        mac.init(new SecretKeySpec(salt, HKDF_HMAC));
        byte[] prk = mac.doFinal(ikm);
        // Expand
        mac.init(new SecretKeySpec(prk, HKDF_HMAC));
        byte[] okm = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < len) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter);
            t = mac.doFinal();
            int copy = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, okm, pos, copy);
            pos += copy;
            counter++;
        }
        Arrays.fill(prk, (byte) 0);
        return okm;
    }

    /** Timestamp wrapper tolerant to nulls and java.util.Date */
    private record TimestampLike(@Nullable Instant value) {
        static TimestampLike from(@Nullable Object dbVal) {
            if (dbVal == null) return new TimestampLike(null);
            if (dbVal instanceof java.sql.Timestamp ts) return new TimestampLike(ts.toInstant());
            if (dbVal instanceof java.util.Date d)     return new TimestampLike(d.toInstant());
            return new TimestampLike(null);
        }
        boolean isExpired(Instant now) { return value != null && now.isAfter(value); }
    }

    // -------------------------------------------------------------------------------------
    // Exceptions
    // -------------------------------------------------------------------------------------

    public static class VaultConfigException extends RuntimeException {
        public VaultConfigException(String msg) { super(msg); }
        public VaultConfigException(String msg, Throwable t) { super(msg, t); }
    }

    public static class VaultCryptoException extends RuntimeException {
        public VaultCryptoException(String msg, Throwable t) { super(msg, t); }
    }

    public static class VaultPersistenceException extends RuntimeException {
        public VaultPersistenceException(String msg) { super(msg); }
        public VaultPersistenceException(String msg, Throwable t) { super(msg, t); }
    }

    // -------------------------------------------------------------------------------------
    // Properties bridge (to be implemented by the starter properties)
    // -------------------------------------------------------------------------------------

    /** Minimal config interface implemented by the starter's properties. */
    public interface PiiVaultConfig {
        String getActiveKid();
        Map<String, String> getMasterKeys();
        @Nullable Duration getDefaultTtl(); // may be null
        int getMaxPayloadBytes();
        int getSaltBytes();
        int getIvBytes();
        boolean isFailIfMissingKey();
        /** Return raw key bytes for a given KID, or null if absent. */
        @Nullable byte[] masterKeyBytes(String kid);
    }

    // Validation
    private void validateKeys() {
        Map<String, String> map = props.getMasterKeys();
        if (map == null || map.isEmpty()) {
            if (props.isFailIfMissingKey()) {
                throw new VaultConfigException("No master keys configured under veggieshop.pii.vault.master-keys");
            } else {
                log.warn("PII Vault: master-keys map is empty; operations may fail until configured");
            }
        }
        if (map == null || !map.containsKey(props.getActiveKid())) {
            if (props.isFailIfMissingKey()) {
                throw new VaultConfigException("Active KID not present in master-keys: " + props.getActiveKid());
            } else {
                log.warn("PII Vault: active KID {} not in master-keys; new writes will fallback if allowed", props.getActiveKid());
            }
        }
    }

    /** Private helper for hard delete (idempotent). */
    private boolean hardDeleteRow(String tenantId, String ref) {
        int rows = jdbc.update(
                "DELETE FROM pii_vault WHERE tenant_id=? AND pii_ref=?",
                tenantId, java.util.UUID.fromString(ref)
        );
        if (rows > 0) {
            if (mDelOk != null) mDelOk.increment();
            log.info("PII deleted: piiRef={}, tenant={}", ref, tenantId);
            return true;
        } else {
            if (mDelErr != null) mDelErr.increment();
            return false;
        }
    }
}
