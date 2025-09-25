package io.veggieshop.platform.messaging.kafka;

import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.internals.RecordHeaders;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.function.Predicate;

/**
 * Small, dependency-free utility for working with Kafka record headers in a consistent, safe, and testable way.
 *
 * <p>Design notes:
 * <ul>
 *   <li>Header names are ASCII, lower-kebab-case, and validated. Values are binary-safe byte arrays.</li>
 *   <li>String/UUID/number/Instant helpers encode/decode to/from UTF-8 (except numeric primitives which use
 *       fixed-length big-endian binary for compactness).</li>
 *   <li>Provides a minimal envelope for platform-wide keys (tenant, trace, schema fingerprint, entity version).</li>
 *   <li>No PII should ever be placed in headers; only routing/observability metadata is allowed.</li>
 *   <li>Does not depend on Spring; callers can use with both ProducerRecord and ConsumerRecord.</li>
 * </ul>
 * </p>
 */
public final class Headers {

    /** Max allowed header value size (in bytes) to avoid accidental payload bloat. */
    public static final int MAX_HEADER_VALUE_BYTES = 8 * 1024;

    /** UTF-8 shared constant shortcut. */
    private static final java.nio.charset.Charset UTF8 = StandardCharsets.UTF_8;

    private Headers() {}

    // ---------------------------------------------------------------------
    // Canonical keys used across VeggieShop (contract-first envelope)
    // ---------------------------------------------------------------------
    public static final class Keys {
        private Keys() {}

        /** W3C Trace Context header (if present, must be forwarded as-is). */
        public static final String TRACEPARENT = "traceparent";
        /** W3C baggage header (if present, must be forwarded as-is). */
        public static final String BAGGAGE = "baggage";

        /** Internal: tenant identifier (string). */
        public static final String TENANT_ID = "x-tenant-id";
        /** Internal: schema fingerprint (sha256 or similar; string). */
        public static final String SCHEMA_FINGERPRINT = "x-schema-fingerprint";
        /** Internal: application trace id (string). Prefer W3C traceparent; keep for compatibility. */
        public static final String TRACE_ID = "x-trace-id";
        /** Internal: numeric entity version (long). */
        public static final String ENTITY_VERSION = "x-entity-version";
        /** Optional: idempotency or event id (UUID string). */
        public static final String EVENT_ID = "x-event-id";
        /** Optional: request correlation id (string). */
        public static final String REQUEST_ID = "x-request-id";

        /** Returns true if the header name is safe to propagate downstream (no PII, only meta). */
        public static boolean isSafeToPropagate(String key) {
            String k = canonicalKey(key);
            return k.equals(TRACEPARENT)
                    || k.equals(BAGGAGE)
                    || k.startsWith("x-");
        }
    }

    // ---------------------------------------------------------------------
    // Factory
    // ---------------------------------------------------------------------
    /** Create empty headers instance. */
    public static org.apache.kafka.common.header.Headers create() {
        return new RecordHeaders();
    }

    /** Defensive copy of headers (ignores invalid names). */
    public static org.apache.kafka.common.header.Headers copyOf(org.apache.kafka.common.header.Headers src) {
        RecordHeaders dst = new RecordHeaders();
        if (src == null) return dst;
        for (Header h : src) {
            String key = safeOrNull(h.key());
            if (key == null) continue;
            byte[] value = h.value() == null ? null : Arrays.copyOf(h.value(), h.value().length);
            dst.add(key, value);
        }
        return dst;
    }

    // ---------------------------------------------------------------------
    // Put (overwrites existing key)
    // ---------------------------------------------------------------------
    public static void put(org.apache.kafka.common.header.Headers headers, String key, byte[] value) {
        Objects.requireNonNull(headers, "headers");
        String k = canonicalKey(key);
        validateSize(value);
        headers.remove(k);
        headers.add(k, value);
    }

    public static void put(org.apache.kafka.common.header.Headers headers, String key, String value) {
        put(headers, key, value == null ? null : value.getBytes(UTF8));
    }

    public static void putUuid(org.apache.kafka.common.header.Headers headers, String key, UUID value) {
        if (value == null) {
            put(headers, key, (byte[]) null);
            return;
        }
        ByteBuffer bb = ByteBuffer.allocate(16);
        bb.putLong(value.getMostSignificantBits());
        bb.putLong(value.getLeastSignificantBits());
        put(headers, key, bb.array());
    }

    public static void putLong(org.apache.kafka.common.header.Headers headers, String key, long value) {
        ByteBuffer bb = ByteBuffer.allocate(Long.BYTES);
        bb.putLong(value);
        put(headers, key, bb.array());
    }

    public static void putInt(org.apache.kafka.common.header.Headers headers, String key, int value) {
        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES);
        bb.putInt(value);
        put(headers, key, bb.array());
    }

    public static void putInstant(org.apache.kafka.common.header.Headers headers, String key, Instant value) {
        if (value == null) {
            put(headers, key, (byte[]) null);
        } else {
            putLong(headers, key, value.toEpochMilli());
        }
    }

    // ---------------------------------------------------------------------
    // Put-if-absent
    // ---------------------------------------------------------------------
    public static void putIfAbsent(org.apache.kafka.common.header.Headers headers, String key, byte[] value) {
        if (!has(headers, key)) {
            put(headers, key, value);
        }
    }

    public static void putIfAbsent(org.apache.kafka.common.header.Headers headers, String key, String value) {
        if (!has(headers, key)) {
            put(headers, key, value);
        }
    }

    public static void putUuidIfAbsent(org.apache.kafka.common.header.Headers headers, String key, UUID value) {
        if (!has(headers, key)) {
            putUuid(headers, key, value);
        }
    }

    public static void putLongIfAbsent(org.apache.kafka.common.header.Headers headers, String key, long value) {
        if (!has(headers, key)) {
            putLong(headers, key, value);
        }
    }

    public static void putInstantIfAbsent(org.apache.kafka.common.header.Headers headers, String key, Instant value) {
        if (!has(headers, key)) {
            putInstant(headers, key, value);
        }
    }

    // ---------------------------------------------------------------------
    // Get
    // ---------------------------------------------------------------------
    public static boolean has(org.apache.kafka.common.header.Headers headers, String key) {
        if (headers == null) return false;
        String k = canonicalKey(key);
        return headers.lastHeader(k) != null;
    }

    public static Optional<byte[]> get(org.apache.kafka.common.header.Headers headers, String key) {
        if (headers == null) return Optional.empty();
        Header h = headers.lastHeader(canonicalKey(key));
        return h == null ? Optional.empty() : Optional.ofNullable(h.value());
    }

    public static Optional<String> getAsString(org.apache.kafka.common.header.Headers headers, String key) {
        return get(headers, key).map(v -> v == null ? null : new String(v, UTF8));
    }

    public static Optional<UUID> getAsUuid(org.apache.kafka.common.header.Headers headers, String key) {
        return get(headers, key).flatMap(v -> {
            if (v == null) return Optional.empty();
            if (v.length == 16) {
                ByteBuffer bb = ByteBuffer.wrap(v);
                return Optional.of(new UUID(bb.getLong(), bb.getLong()));
            }
            // Fallback: try UTF-8 textual UUID (e.g., when produced by other services)
            try {
                return Optional.of(UUID.fromString(new String(v, UTF8)));
            } catch (Exception ignore) {
                return Optional.empty();
            }
        });
    }

    public static Optional<Long> getAsLong(org.apache.kafka.common.header.Headers headers, String key) {
        return get(headers, key).flatMap(v -> {
            if (v == null) return Optional.empty();
            if (v.length == Long.BYTES) {
                return Optional.of(ByteBuffer.wrap(v).getLong());
            }
            try {
                return Optional.of(Long.parseLong(new String(v, UTF8)));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        });
    }

    public static Optional<Integer> getAsInt(org.apache.kafka.common.header.Headers headers, String key) {
        return get(headers, key).flatMap(v -> {
            if (v == null) return Optional.empty();
            if (v.length == Integer.BYTES) {
                return Optional.of(ByteBuffer.wrap(v).getInt());
            }
            try {
                return Optional.of(Integer.parseInt(new String(v, UTF8)));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        });
    }

    public static Optional<Instant> getAsInstant(org.apache.kafka.common.header.Headers headers, String key) {
        return getAsLong(headers, key).map(Instant::ofEpochMilli);
    }

    // ---------------------------------------------------------------------
    // Envelope helpers (applies canonical platform headers)
    // ---------------------------------------------------------------------

    /**
     * Attach the standard envelope keys if not present yet.
     * This is safe to call multiple times as it uses put-if-absent semantics.
     */
    public static void attachEnvelope(org.apache.kafka.common.header.Headers headers,
                                      String tenantId,
                                      String traceId,
                                      String schemaFingerprint,
                                      Long entityVersion) {
        Objects.requireNonNull(headers, "headers");

        if (tenantId != null && !tenantId.isBlank()) {
            putIfAbsent(headers, Keys.TENANT_ID, tenantId);
        }
        if (traceId != null && !traceId.isBlank()) {
            // Prefer W3C traceparent if caller provided it; x-trace-id remains for legacy consumers
            putIfAbsent(headers, Keys.TRACE_ID, traceId);
        }
        if (schemaFingerprint != null && !schemaFingerprint.isBlank()) {
            putIfAbsent(headers, Keys.SCHEMA_FINGERPRINT, schemaFingerprint);
        }
        if (entityVersion != null) {
            putLongIfAbsent(headers, Keys.ENTITY_VERSION, entityVersion);
        }
    }

    /**
     * Propagate a minimal W3C trace context if already present on incoming headers.
     * No new context is created here; generation should happen at the caller (HTTP filter or consumer).
     */
    public static void propagateW3CTraceContext(org.apache.kafka.common.header.Headers incoming,
                                                org.apache.kafka.common.header.Headers outgoing) {
        if (incoming == null || outgoing == null) return;
        get(incoming, Keys.TRACEPARENT).ifPresent(v -> put(outgoing, Keys.TRACEPARENT, v));
        get(incoming, Keys.BAGGAGE).ifPresent(v -> put(outgoing, Keys.BAGGAGE, v));
    }

    /**
     * Copy headers based on a predicate (e.g., Keys::isSafeToPropagate).
     * Existing keys on the destination are overwritten.
     */
    public static void copy(org.apache.kafka.common.header.Headers from,
                            org.apache.kafka.common.header.Headers to,
                            Predicate<String> keyPredicate) {
        if (from == null || to == null) return;
        for (Header h : from) {
            String key = safeOrNull(h.key());
            if (key == null) continue;
            if (keyPredicate != null && !keyPredicate.test(key)) continue;
            put(to, key, h.value() == null ? null : Arrays.copyOf(h.value(), h.value().length));
        }
    }

    // ---------------------------------------------------------------------
    // Validation & utils
    // ---------------------------------------------------------------------
    /** Enforce ASCII lower-kebab-case names and trim spaces. */
    public static String canonicalKey(String key) {
        String k = safeOrNull(key);
        if (k == null) throw new IllegalArgumentException("Header key must be non-empty");
        // only 'a-z', '0-9', '-', and '.' are allowed ('.' to interop with some Confluent tools)
        for (int i = 0; i < k.length(); i++) {
            char c = k.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '.';
            if (!ok) {
                throw new IllegalArgumentException("Invalid header key '" + key + "' at index " + i +
                        " (only lowercase letters, digits, '-' and '.' are allowed)");
            }
        }
        return k;
    }

    private static String safeOrNull(String key) {
        if (key == null) return null;
        String trimmed = key.trim().toLowerCase(Locale.ROOT);
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static void validateSize(byte[] value) {
        if (value == null) return;
        if (value.length > MAX_HEADER_VALUE_BYTES) {
            throw new IllegalArgumentException("Header value exceeds " + MAX_HEADER_VALUE_BYTES + " bytes");
        }
    }
}
