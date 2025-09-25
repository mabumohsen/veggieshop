package io.veggieshop.platform.application.consistency.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * ConsistencyToken
 *
 * A compact, signed token that carries a tenant-scoped "read-your-writes" watermark.
 * Format (compact string):  CT1.&lt;kid&gt;.&lt;base64url(payload)&gt;.&lt;base64url(signature)&gt;
 *
 * - "CT1"           : version prefix (string literal)
 * - kid             : key id used by the signer for rotation
 * - payload (JSON)  : {"t": "...", "iat": 1700000000000, "wm": 1700000000420, "ver": 15}
 * - signature       : HMAC over bytes("CT1." + kid + "." + base64url(payload))
 *
 * JSON field names are short on purpose:
 *  - t   : tenant id (string)
 *  - iat : issued-at epoch millis (long)
 *  - wm  : watermark (epoch millis of last write observed) (long) — monotonic per tenant
 *  - ver : optional entity version if relevant to a specific aggregate (nullable)
 *
 * This type is framework-agnostic and uses only Jackson for JSON.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({ "t", "iat", "wm", "ver" })
public final class ConsistencyToken implements Serializable {

    @Serial private static final long serialVersionUID = 1L;

    /** Compact format prefix; part of the signed bytes to bind the version. */
    public static final String PREFIX = "CT1";

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    // ----------------- Payload (immutable) -----------------

    @JsonProperty("t")
    private final String tenant;

    @JsonProperty("iat")
    private final long issuedAtMillis;

    @JsonProperty("wm")
    private final long watermarkMillis;

    @JsonProperty("ver")
    private final Long version; // optional

    // ----------------- Constructors / factories -----------------

    private ConsistencyToken(String tenant, long issuedAtMillis, long watermarkMillis, Long version) {
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("tenant must be non-empty");
        }
        if (issuedAtMillis <= 0L) {
            throw new IllegalArgumentException("issuedAtMillis must be > 0");
        }
        if (watermarkMillis <= 0L) {
            throw new IllegalArgumentException("watermarkMillis must be > 0");
        }
        this.tenant = tenant.trim();
        this.issuedAtMillis = issuedAtMillis;
        this.watermarkMillis = watermarkMillis;
        this.version = version;
    }

    /**
     * Create a token using the provided clock for iat and a watermark.
     */
    public static ConsistencyToken of(String tenant, long watermarkMillis, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        return new ConsistencyToken(tenant, clock.millis(), watermarkMillis, null);
    }

    /**
     * Create a token with explicit values.
     */
    public static ConsistencyToken of(String tenant, long issuedAtMillis, long watermarkMillis, Long version) {
        return new ConsistencyToken(tenant, issuedAtMillis, watermarkMillis, version);
    }

    // ----------------- Accessors -----------------

    public String tenant() { return tenant; }

    public long issuedAtMillis() { return issuedAtMillis; }

    public long watermarkMillis() { return watermarkMillis; }

    public Optional<Long> version() { return Optional.ofNullable(version); }

    public boolean isExpired(long ttlMillis, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        if (ttlMillis <= 0) return false;
        long now = clock.millis();
        return (issuedAtMillis + ttlMillis) < now;
    }

    // ----------------- Encoding / decoding -----------------

    /**
     * Encode as compact string and sign using the given signer.
     */
    public String encode(TokenSigner signer) {
        Objects.requireNonNull(signer, "signer");
        final String kid = signer.activeKeyId();
        if (kid == null || kid.isBlank()) {
            throw new IllegalStateException("TokenSigner.activeKeyId() must return a non-empty key id");
        }

        final byte[] payloadBytes = writeJsonBytes(this);
        final String payloadB64 = b64url(payloadBytes);

        final String toSign = PREFIX + "." + kid + "." + payloadB64;
        final byte[] sig = signer.sign(kid, toSign.getBytes(StandardCharsets.UTF_8));
        final String sigB64 = b64url(sig);

        return PREFIX + "." + kid + "." + payloadB64 + "." + sigB64;
    }

    /**
     * Parse + verify a compact token string. Returns empty if verification fails or format is invalid.
     */
    public static Optional<ConsistencyToken> parseAndVerify(String compact, TokenSigner signer) {
        Objects.requireNonNull(signer, "signer");
        if (compact == null || compact.isBlank()) return Optional.empty();

        String[] parts = compact.split("\\.", 4);
        if (parts.length != 4) return Optional.empty();
        if (!PREFIX.equals(parts[0])) return Optional.empty();

        String kid = parts[1];
        String payloadB64 = parts[2];
        String sigB64 = parts[3];

        if (kid == null || kid.isBlank() || payloadB64.isBlank() || sigB64.isBlank()) {
            return Optional.empty();
        }

        byte[] payload = b64urlDecode(payloadB64);
        byte[] sig = b64urlDecode(sigB64);

        final String toSign = PREFIX + "." + kid + "." + payloadB64;
        boolean ok = signer.verify(kid, toSign.getBytes(StandardCharsets.UTF_8), sig);
        if (!ok) return Optional.empty();

        return readJson(payload);
    }

    // ----------------- JSON helpers -----------------

    private static byte[] writeJsonBytes(ConsistencyToken token) {
        try {
            return MAPPER.writeValueAsBytes(token);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize ConsistencyToken", e);
        }
    }

    private static Optional<ConsistencyToken> readJson(byte[] bytes) {
        try {
            return Optional.of(MAPPER.readValue(bytes, ConsistencyToken.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // ----------------- Base64url helpers -----------------

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private static String b64url(byte[] bytes) {
        return URL_ENCODER.encodeToString(bytes);
    }

    private static byte[] b64urlDecode(String s) {
        return URL_DECODER.decode(s);
    }

    // ----------------- Equality / hash / toString -----------------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConsistencyToken that)) return false;
        return issuedAtMillis == that.issuedAtMillis
                && watermarkMillis == that.watermarkMillis
                && Objects.equals(tenant, that.tenant)
                && Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tenant, issuedAtMillis, watermarkMillis, version);
    }

    @Override
    public String toString() {
        // safe/log-friendly (no secrets); show ISO-8601 for human readability
        return "ConsistencyToken{tenant='" + tenant + "', iat=" + Instant.ofEpochMilli(issuedAtMillis)
                + ", wm=" + Instant.ofEpochMilli(watermarkMillis)
                + (version != null ? ", ver=" + version : "") + "}";
    }
}
