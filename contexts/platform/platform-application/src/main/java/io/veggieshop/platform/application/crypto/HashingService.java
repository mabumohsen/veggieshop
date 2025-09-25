package io.veggieshop.platform.application.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Plain utility; no Spring annotations here. */
public final class HashingService {

    private static final int STREAM_BUFFER = 16 * 1024;

    // Canonical JSON for stable hashing (sorted keys, no pretty-print)
    private static final ObjectMapper CANONICAL_JSON = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .disable(SerializationFeature.INDENT_OUTPUT);

    private final EnumMap<HashAlgorithm, ThreadLocal<MessageDigest>> digests =
            new EnumMap<>(HashAlgorithm.class);

    public HashingService() {
        for (HashAlgorithm alg : HashAlgorithm.values()) {
            digests.put(alg, ThreadLocal.withInitial(() -> newDigest(alg.jcaName)));
        }
    }

    // -------- Digests --------
    public byte[] digest(@NotNull byte[] input, @NotNull HashAlgorithm alg) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(alg, "alg");
        MessageDigest md = digests.get(alg).get();
        md.reset();
        return md.digest(input);
    }

    public byte[] digest(@NotNull String input, @NotNull HashAlgorithm alg) {
        Objects.requireNonNull(input, "input");
        String norm = Normalizer.normalize(input, Normalizer.Form.NFKC);
        return digest(norm.getBytes(StandardCharsets.UTF_8), alg);
    }

    public byte[] digest(@NotNull InputStream in, @NotNull HashAlgorithm alg) throws IOException {
        Objects.requireNonNull(in, "in");
        MessageDigest md = digests.get(alg).get();
        md.reset();
        try (DigestInputStream dis = new DigestInputStream(in, md)) {
            byte[] buf = new byte[STREAM_BUFFER];
            while (dis.read(buf) != -1) { /* DigestInputStream updates md */ }
        }
        return md.digest();
    }

    public String fingerprintHex(@NotNull byte[] input, @NotNull HashAlgorithm alg) {
        return alg.scheme + ":" + HexFormat.of().formatHex(digest(input, alg));
    }

    public String digestBase64(@NotNull byte[] input, @NotNull HashAlgorithm alg, boolean urlSafe) {
        byte[] d = digest(input, alg);
        return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder()).encodeToString(d);
    }

    // -------- HMAC --------
    public byte[] hmac(@NotNull byte[] secretKey, @NotNull byte[] message, @NotNull HmacAlgorithm alg) {
        Objects.requireNonNull(secretKey, "secretKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(alg, "alg");
        try {
            Mac mac = Mac.getInstance(alg.jcaName);
            mac.init(new SecretKeySpec(secretKey, alg.jcaName));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC algorithm not available: " + alg.jcaName, e);
        }
    }

    public String hmacHex(@NotNull byte[] secretKey, @NotNull byte[] message, @NotNull HmacAlgorithm alg) {
        return HexFormat.of().formatHex(hmac(secretKey, message, alg));
    }

    public String hmacBase64(@NotNull byte[] secretKey, @NotNull byte[] message, @NotNull HmacAlgorithm alg, boolean urlSafe) {
        byte[] mac = hmac(secretKey, message, alg);
        return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder()).encodeToString(mac);
    }

    // -------- Canonical JSON hashing --------
    public byte[] digestCanonicalJson(@NotNull Object value, @NotNull HashAlgorithm alg) {
        try {
            byte[] canonical = CANONICAL_JSON.writeValueAsBytes(value);
            return digest(canonical, alg);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize value to canonical JSON", e);
        }
    }

    // -------- Request hash (idempotency) --------
    public byte[] computeRequestHash(
            @NotBlank String httpMethod,
            @NotBlank String path,
            @NotNull Map<String, String> selectedHeaders,
            @NotNull byte[] body,
            @NotNull HashAlgorithm alg
    ) {
        // Canonicalize + sort headers
        Map<String, String> canonicalHeaders = new LinkedHashMap<>();
        selectedHeaders.entrySet().stream()
                .sorted(Comparator.comparing(e -> e.getKey().toLowerCase()))
                .forEach(e -> canonicalHeaders.put(
                        e.getKey().toLowerCase(),
                        e.getValue() == null ? "" : Normalizer.normalize(e.getValue(), Normalizer.Form.NFKC))
                );

        byte[] methodBytes = Normalizer.normalize(httpMethod.trim(), Normalizer.Form.NFKC)
                .getBytes(StandardCharsets.UTF_8);
        byte[] pathBytes = Normalizer.normalize(path, Normalizer.Form.NFKC)
                .getBytes(StandardCharsets.UTF_8);

        // بدلاً من Map.toString() الغير مُعرّف بدقة، استخدم JSON قانوني مستقر:
        byte[] headersBytes;
        try {
            headersBytes = CANONICAL_JSON.writeValueAsBytes(canonicalHeaders);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize headers to canonical JSON", e);
        }

        byte[] framed = frame(methodBytes, pathBytes, headersBytes, body);
        return digest(framed, alg);
    }

    // -------- Audit chaining --------
    public byte[] chainAudit(@NotNull byte[] previousHashOrEmpty, @NotNull byte[] payload, @NotNull HashAlgorithm alg) {
        return digest(frame(previousHashOrEmpty, payload), alg);
    }

    public byte[] chainAuditHex(@NotNull String previousHashHexOrEmpty, @NotNull byte[] payload, @NotNull HashAlgorithm alg) {
        byte[] prev = previousHashHexOrEmpty.isBlank() ? new byte[0] : HexFormat.of().parseHex(previousHashHexOrEmpty);
        return chainAudit(prev, payload, alg);
    }

    // -------- Utilities --------
    public boolean constantTimeEquals(@NotNull byte[] a, @NotNull byte[] b) {
        if (a.length != b.length) return false;
        int r = 0; for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }

    public byte[] parseFingerprint(@NotBlank String fingerprint, @NotNull HashAlgorithm expectedAlg) {
        int idx = fingerprint.indexOf(':');
        if (idx <= 0) throw new IllegalArgumentException("Invalid fingerprint (missing scheme): " + fingerprint);
        String scheme = fingerprint.substring(0, idx);
        if (!scheme.equalsIgnoreCase(expectedAlg.scheme)) {
            throw new IllegalArgumentException("Unexpected scheme: " + scheme + " (expected " + expectedAlg.scheme + ")");
        }
        String hex = fingerprint.substring(idx + 1);
        return HexFormat.of().parseHex(hex);
    }

    public String toHex(@NotNull byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    public String toBase64(@NotNull byte[] bytes, boolean urlSafe) {
        return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder()).encodeToString(bytes);
    }

    // -------- Internals --------
    private static MessageDigest newDigest(String jcaName) {
        try { return MessageDigest.getInstance(jcaName); }
        catch (GeneralSecurityException e) { throw new IllegalStateException("Digest algorithm not available: " + jcaName, e); }
    }

    /** length-prefixed framing: [len(x1)][x1][len(x2)][x2]... */
    private static byte[] frame(byte[]... parts) {
        int size = 0; for (byte[] p : parts) size += 4 + p.length;
        ByteBuffer buf = ByteBuffer.allocate(size);
        for (byte[] p : parts) { buf.putInt(p.length); buf.put(p); }
        return buf.array();
    }

    // -------- Enums --------
    public enum HashAlgorithm {
        SHA_256("sha256", "SHA-256"),
        SHA_512_256("sha512-256", "SHA-512/256"),
        SHA3_256("sha3-256", "SHA3-256");

        public final String scheme;
        public final String jcaName;
        HashAlgorithm(String scheme, String jcaName) { this.scheme = scheme; this.jcaName = jcaName; }
    }

    public enum HmacAlgorithm {
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA512("HmacSHA512");
        public final String jcaName;
        HmacAlgorithm(String jcaName) { this.jcaName = jcaName; }
    }
}
