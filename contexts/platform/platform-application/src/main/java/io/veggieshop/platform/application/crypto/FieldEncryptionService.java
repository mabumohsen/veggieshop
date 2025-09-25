package io.veggieshop.platform.application.crypto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

public class FieldEncryptionService {

    private static final String ENVELOPE_VERSION = "vse1";
    private static final String ALG_AES_GCM = "AES-GCM";
    private static final String JCA_TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private static final String TOKEN_VERSION = "vst1";
    private static final String HMAC_ALG = "HmacSHA256";
    private static final int TOKEN_BYTES = 16;

    private final CryptoKeyProvider keyProvider;
    private final SecureRandom secureRandom;
    private final Clock clock;

    public FieldEncryptionService(CryptoKeyProvider keyProvider) {
        this(keyProvider, new SecureRandom(), Clock.systemUTC());
    }
    public FieldEncryptionService(CryptoKeyProvider keyProvider, SecureRandom secureRandom, Clock clock) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public String encryptString(@NotBlank String tenantId,
                                @NotBlank String fieldPath,
                                @NotBlank String purpose,
                                @NotNull String plaintext) {
        byte[] clear = normalizedUtf8(plaintext);
        String kid = keyProvider.currentKeyId(CryptoKeyUse.AEAD);
        SecretKey key = keyProvider.resolveKey(kid, CryptoKeyUse.AEAD);

        byte[] iv = new byte[IV_LEN];
        secureRandom.nextBytes(iv);

        byte[] aad = buildAad(tenantId, fieldPath, purpose, kid);

        try {
            Cipher cipher = Cipher.getInstance(JCA_TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad);
            byte[] ct = cipher.doFinal(clear);
            return encodeEnvelope(kid, iv, ct);
        } catch (GeneralSecurityException e) {
            throw new FieldCryptoException("AES-GCM encryption failed", e);
        }
    }

    public String decryptToString(@NotBlank String tenantId,
                                  @NotBlank String fieldPath,
                                  @NotBlank String purpose,
                                  @NotBlank String envelope) {
        ParsedEnvelope parsed = decodeEnvelope(envelope);
        if (!ALG_AES_GCM.equals(parsed.algorithm())) {
            throw new FieldCryptoException("Unsupported algorithm: " + parsed.algorithm());
        }
        SecretKey key = keyProvider.resolveKey(parsed.kid(), CryptoKeyUse.AEAD);
        byte[] aad = buildAad(tenantId, fieldPath, purpose, parsed.kid());

        try {
            Cipher cipher = Cipher.getInstance(JCA_TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, parsed.iv()));
            cipher.updateAAD(aad);
            byte[] clear = cipher.doFinal(parsed.ciphertext());
            return new String(clear, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new FieldCryptoException("AES-GCM decryption failed (AAD/kid mismatch or corrupted data)", e);
        }
    }

    public String reencrypt(@NotBlank String tenantId,
                            @NotBlank String fieldPath,
                            @NotBlank String purpose,
                            @NotBlank String oldEnvelope) {
        String clear = decryptToString(tenantId, fieldPath, purpose, oldEnvelope);
        return encryptString(tenantId, fieldPath, purpose, clear);
    }

    public String tokenForEquality(@NotBlank String tenantId,
                                   @NotBlank String fieldPath,
                                   @NotBlank String purpose,
                                   @NotNull String value) {
        String kid = keyProvider.currentKeyId(CryptoKeyUse.HMAC);
        SecretKey macKey = keyProvider.resolveKey(kid, CryptoKeyUse.HMAC);
        byte[] aad = buildAad(tenantId, fieldPath, purpose, kid);
        byte[] framed = frame(aad, normalizedUtf8(value));
        byte[] mac = hmac(macKey, framed);
        byte[] truncated = new byte[TOKEN_BYTES];
        System.arraycopy(mac, 0, truncated, 0, TOKEN_BYTES);
        return TOKEN_VERSION + ":" + kid + ":" + B64URL_ENC.encodeToString(truncated);
    }

    public boolean tokenMatches(@NotBlank String tenantId,
                                @NotBlank String fieldPath,
                                @NotBlank String purpose,
                                @NotBlank String token,
                                @NotNull String candidateValue) {
        ParsedToken t = decodeToken(token);
        SecretKey macKey = keyProvider.resolveKey(t.kid(), CryptoKeyUse.HMAC);
        byte[] aad = buildAad(tenantId, fieldPath, purpose, t.kid());
        byte[] framed = frame(aad, normalizedUtf8(candidateValue));
        byte[] mac = hmac(macKey, framed);
        byte[] truncated = new byte[TOKEN_BYTES];
        System.arraycopy(mac, 0, truncated, 0, TOKEN_BYTES);
        return constantTimeEquals(truncated, t.mac());
    }

    private static byte[] normalizedUtf8(String s) {
        String norm = java.text.Normalizer.normalize(Objects.requireNonNull(s), java.text.Normalizer.Form.NFKC);
        return norm.getBytes(StandardCharsets.UTF_8);
    }
    private static byte[] frame(byte[]... parts) {
        int size = 0; for (byte[] p : parts) size += 4 + p.length;
        java.nio.ByteBuffer buf = ByteBuffer.allocate(size);
        for (byte[] p : parts) { buf.putInt(p.length); buf.put(p); }
        return buf.array();
    }
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0; for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]); return r == 0;
    }
    private static byte[] hmac(SecretKey key, byte[] data) {
        try { javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HMAC_ALG); mac.init(key); return mac.doFinal(data); }
        catch (GeneralSecurityException e) { throw new FieldCryptoException("HMAC failure", e); }
    }
    private byte[] buildAad(String tenantId, String fieldPath, String purpose, String kid) {
        String aad = "v=1;t=" + tenantId + ";f=" + fieldPath + ";p=" + purpose + ";alg=" + ALG_AES_GCM + ";kid=" + kid;
        return aad.getBytes(StandardCharsets.US_ASCII);
    }
    private String encodeEnvelope(String kid, byte[] iv, byte[] ct) {
        if (iv.length != IV_LEN) throw new IllegalArgumentException("Unexpected IV length");
        return ENVELOPE_VERSION + ":" + ALG_AES_GCM + ":" + kid + ":" +
                Base64.getUrlEncoder().withoutPadding().encodeToString(iv) + ":" +
                Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
    }
    private ParsedEnvelope decodeEnvelope(String envelope) {
        String[] parts = Optional.ofNullable(envelope).map(s -> s.split(":", 5))
                .orElseThrow(() -> new FieldCryptoException("Envelope is null"));
        if (parts.length != 5) throw new FieldCryptoException("Invalid envelope format");
        if (!ENVELOPE_VERSION.equals(parts[0])) throw new FieldCryptoException("Unsupported envelope version: " + parts[0]);
        byte[] iv = Base64.getUrlDecoder().decode(parts[3]);
        if (iv.length != IV_LEN) throw new FieldCryptoException("Invalid IV length: " + iv.length);
        return new ParsedEnvelope(parts[1], parts[2], iv, Base64.getUrlDecoder().decode(parts[4]));
    }
    private ParsedToken decodeToken(String token) {
        String[] parts = Optional.ofNullable(token).map(s -> s.split(":", 3))
                .orElseThrow(() -> new FieldCryptoException("Token is null"));
        if (parts.length != 3) throw new FieldCryptoException("Invalid token format");
        if (!TOKEN_VERSION.equals(parts[0])) throw new FieldCryptoException("Unsupported token version: " + parts[0]);
        byte[] mac = Base64.getUrlDecoder().decode(parts[2]);
        if (mac.length != TOKEN_BYTES) throw new FieldCryptoException("Invalid token MAC length: " + mac.length);
        return new ParsedToken(parts[1], mac);
    }

    private record ParsedEnvelope(String algorithm, String kid, byte[] iv, byte[] ciphertext) { }
    private record ParsedToken(String kid, byte[] mac) { }

    public static class FieldCryptoException extends RuntimeException {
        public FieldCryptoException(String msg) { super(msg); }
        public FieldCryptoException(String msg, Throwable cause) { super(msg, cause); }
    }
}
