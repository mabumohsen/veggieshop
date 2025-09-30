package io.veggieshop.platform.messaging.kafka;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.internals.RecordHeaders;

/**
 * Utility helpers for Kafka record headers with strict validation and zero external dependencies.
 *
 * <p>Design:
 *
 * <ul>
 *   <li>Header names are ASCII, lower-kebab-case; values are byte arrays (binary-safe).
 *   <li>String/UUID/number/Instant codecs provided; numerics stored as fixed-length big-endian.
 *   <li>“Envelope” helpers for platform keys (tenant, trace, schema fingerprint, entity version).
 *   <li>No PII in headers; only routing/observability metadata is allowed.
 *   <li>Independent of Spring; works with ProducerRecord/ConsumerRecord headers.
 * </ul>
 */
public final class Headers {

  /** Max allowed header value size (bytes) to avoid payload bloat. */
  public static final int MAX_HEADER_VALUE_BYTES = 8 * 1024;

  /** Shared UTF-8 constant. */
  private static final java.nio.charset.Charset UTF8 = StandardCharsets.UTF_8;

  private Headers() {
    // utility class
  }

  // ---------------------------------------------------------------------
  // Canonical keys (contract-first envelope)
  // ---------------------------------------------------------------------

  /** Canonical header keys used across the platform. */
  public static final class Keys {
    private Keys() {}

    /** W3C Trace Context header (forward as-is if present). */
    public static final String TRACEPARENT = "traceparent";

    /** W3C baggage header (forward as-is if present). */
    public static final String BAGGAGE = "baggage";

    /** Internal: tenant identifier (string). */
    public static final String TENANT_ID = "x-tenant-id";

    /** Internal: schema fingerprint (sha256 or similar; string). */
    public static final String SCHEMA_FINGERPRINT = "x-schema-fingerprint";

    /** Internal: app trace id (legacy; prefer W3C traceparent). */
    public static final String TRACE_ID = "x-trace-id";

    /** Internal: numeric entity version (long). */
    public static final String ENTITY_VERSION = "x-entity-version";

    /** Optional: idempotency / event id (UUID as string). */
    public static final String EVENT_ID = "x-event-id";

    /** Optional: request correlation id (string). */
    public static final String REQUEST_ID = "x-request-id";

    /**
     * Returns whether a key is safe to propagate downstream (metadata only).
     *
     * @param key header key (any case)
     * @return true if safe
     */
    public static boolean isSafeToPropagate(String key) {
      String k = canonicalKey(key);
      return k.equals(TRACEPARENT) || k.equals(BAGGAGE) || k.startsWith("x-");
    }
  }

  // ---------------------------------------------------------------------
  // Factory
  // ---------------------------------------------------------------------

  /**
   * Creates an empty headers instance.
   *
   * @return new {@link org.apache.kafka.common.header.Headers}
   */
  public static org.apache.kafka.common.header.Headers create() {
    return new RecordHeaders();
  }

  /**
   * Returns a defensive copy of the given headers (skips invalid names).
   *
   * @param src source headers
   * @return copied headers
   */
  public static org.apache.kafka.common.header.Headers copyOf(
      org.apache.kafka.common.header.Headers src) {
    RecordHeaders dst = new RecordHeaders();
    if (src == null) {
      return dst;
    }
    for (Header h : src) {
      String key = safeOrNull(h.key());
      if (key == null) {
        continue;
      }
      byte[] value = h.value() == null ? null : Arrays.copyOf(h.value(), h.value().length);
      dst.add(key, value);
    }
    return dst;
  }

  // ---------------------------------------------------------------------
  // Put (overwrites)
  // ---------------------------------------------------------------------

  /** Puts a raw value (overwrites existing). */
  public static void put(org.apache.kafka.common.header.Headers headers, String key, byte[] value) {
    java.util.Objects.requireNonNull(headers, "headers");
    String k = canonicalKey(key);
    validateSize(value);
    headers.remove(k);
    headers.add(k, value);
  }

  /** Puts a UTF-8 string (overwrites). */
  public static void put(org.apache.kafka.common.header.Headers headers, String key, String value) {
    put(headers, key, value == null ? null : value.getBytes(UTF8));
  }

  /** Puts a UUID as 16 bytes (MSB+LSB, big-endian). */
  public static void putUuid(
      org.apache.kafka.common.header.Headers headers, String key, UUID value) {
    if (value == null) {
      put(headers, key, (byte[]) null);
      return;
    }
    ByteBuffer bb = ByteBuffer.allocate(16);
    bb.putLong(value.getMostSignificantBits());
    bb.putLong(value.getLeastSignificantBits());
    put(headers, key, bb.array());
  }

  /** Puts a long as 8 bytes (big-endian). */
  public static void putLong(
      org.apache.kafka.common.header.Headers headers, String key, long value) {
    ByteBuffer bb = ByteBuffer.allocate(Long.BYTES);
    bb.putLong(value);
    put(headers, key, bb.array());
  }

  /** Puts an int as 4 bytes (big-endian). */
  public static void putInt(org.apache.kafka.common.header.Headers headers, String key, int value) {
    ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES);
    bb.putInt(value);
    put(headers, key, bb.array());
  }

  /** Puts an {@link Instant} as epoch millis (8 bytes). */
  public static void putInstant(
      org.apache.kafka.common.header.Headers headers, String key, Instant value) {
    if (value == null) {
      put(headers, key, (byte[]) null);
    } else {
      putLong(headers, key, value.toEpochMilli());
    }
  }

  // ---------------------------------------------------------------------
  // Put-if-absent
  // ---------------------------------------------------------------------

  /** Puts raw value if absent. */
  public static void putIfAbsent(
      org.apache.kafka.common.header.Headers headers, String key, byte[] value) {
    if (!has(headers, key)) {
      put(headers, key, value);
    }
  }

  /** Puts string value if absent. */
  public static void putIfAbsent(
      org.apache.kafka.common.header.Headers headers, String key, String value) {
    if (!has(headers, key)) {
      put(headers, key, value);
    }
  }

  /** Puts UUID if absent. */
  public static void putUuidIfAbsent(
      org.apache.kafka.common.header.Headers headers, String key, UUID value) {
    if (!has(headers, key)) {
      putUuid(headers, key, value);
    }
  }

  /** Puts long if absent. */
  public static void putLongIfAbsent(
      org.apache.kafka.common.header.Headers headers, String key, long value) {
    if (!has(headers, key)) {
      putLong(headers, key, value);
    }
  }

  /** Puts instant if absent. */
  public static void putInstantIfAbsent(
      org.apache.kafka.common.header.Headers headers, String key, Instant value) {
    if (!has(headers, key)) {
      putInstant(headers, key, value);
    }
  }

  // ---------------------------------------------------------------------
  // Get
  // ---------------------------------------------------------------------

  /** Returns whether a header exists (by canonical key). */
  public static boolean has(org.apache.kafka.common.header.Headers headers, String key) {
    if (headers == null) {
      return false;
    }
    String k = canonicalKey(key);
    return headers.lastHeader(k) != null;
  }

  /** Gets the last value for a key. */
  public static Optional<byte[]> get(org.apache.kafka.common.header.Headers headers, String key) {
    if (headers == null) {
      return Optional.empty();
    }
    Header h = headers.lastHeader(canonicalKey(key));
    return h == null ? Optional.empty() : Optional.ofNullable(h.value());
  }

  /** Gets value as UTF-8 string. */
  public static Optional<String> getAsString(
      org.apache.kafka.common.header.Headers headers, String key) {
    return get(headers, key).map(v -> v == null ? null : new String(v, UTF8));
  }

  /** Gets value as UUID (16 byte binary or textual UUID fallback). */
  public static Optional<UUID> getAsUuid(
      org.apache.kafka.common.header.Headers headers, String key) {
    return get(headers, key)
        .flatMap(
            v -> {
              if (v == null) {
                return Optional.empty();
              }
              if (v.length == 16) {
                ByteBuffer bb = ByteBuffer.wrap(v);
                return Optional.of(new UUID(bb.getLong(), bb.getLong()));
              }
              try {
                return Optional.of(UUID.fromString(new String(v, UTF8)));
              } catch (Exception ignore) {
                return Optional.empty();
              }
            });
  }

  /** Gets value as long (binary or textual). */
  public static Optional<Long> getAsLong(
      org.apache.kafka.common.header.Headers headers, String key) {
    return get(headers, key)
        .flatMap(
            v -> {
              if (v == null) {
                return Optional.empty();
              }
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

  /** Gets value as int (binary or textual). */
  public static Optional<Integer> getAsInt(
      org.apache.kafka.common.header.Headers headers, String key) {
    return get(headers, key)
        .flatMap(
            v -> {
              if (v == null) {
                return Optional.empty();
              }
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

  /** Gets value as {@link Instant} (epoch millis). */
  public static Optional<Instant> getAsInstant(
      org.apache.kafka.common.header.Headers headers, String key) {
    return getAsLong(headers, key).map(Instant::ofEpochMilli);
  }

  // ---------------------------------------------------------------------
  // Envelope helpers
  // ---------------------------------------------------------------------

  /** Attaches standard envelope keys if absent (idempotent). */
  public static void attachEnvelope(
      org.apache.kafka.common.header.Headers headers,
      String tenantId,
      String traceId,
      String schemaFingerprint,
      Long entityVersion) {
    java.util.Objects.requireNonNull(headers, "headers");

    if (tenantId != null && !tenantId.isBlank()) {
      putIfAbsent(headers, Keys.TENANT_ID, tenantId);
    }
    if (traceId != null && !traceId.isBlank()) {
      // Prefer W3C traceparent when provided elsewhere; keep x-trace-id for legacy.
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
   * Propagates W3C trace context if present on incoming headers. No new context is created here.
   *
   * @param incoming source headers
   * @param outgoing destination headers
   */
  public static void propagateW3cTraceContext(
      org.apache.kafka.common.header.Headers incoming,
      org.apache.kafka.common.header.Headers outgoing) {
    if (incoming == null || outgoing == null) {
      return;
    }
    get(incoming, Keys.TRACEPARENT).ifPresent(v -> put(outgoing, Keys.TRACEPARENT, v));
    get(incoming, Keys.BAGGAGE).ifPresent(v -> put(outgoing, Keys.BAGGAGE, v));
  }

  /**
   * Backward-compatible alias for {@link
   * #propagateW3cTraceContext(org.apache.kafka.common.header.Headers,
   * org.apache.kafka.common.header.Headers)}. Kept to avoid breaking older call sites.
   *
   * @deprecated Use {@link #propagateW3cTraceContext(org.apache.kafka.common.header.Headers,
   *     org.apache.kafka.common.header.Headers)}.
   */
  @Deprecated
  @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
  public static void propagateW3CTraceContext(
      org.apache.kafka.common.header.Headers incoming,
      org.apache.kafka.common.header.Headers outgoing) {
    propagateW3cTraceContext(incoming, outgoing);
  }

  /**
   * Copies headers from one carrier to another using a predicate (destination keys overwritten).
   *
   * @param from source headers
   * @param to destination headers
   * @param keyPredicate filter for keys (e.g., {@code Keys::isSafeToPropagate})
   */
  public static void copy(
      org.apache.kafka.common.header.Headers from,
      org.apache.kafka.common.header.Headers to,
      Predicate<String> keyPredicate) {
    if (from == null || to == null) {
      return;
    }
    for (Header h : from) {
      String key = safeOrNull(h.key());
      if (key == null) {
        continue;
      }
      if (keyPredicate != null && !keyPredicate.test(key)) {
        continue;
      }
      put(to, key, h.value() == null ? null : Arrays.copyOf(h.value(), h.value().length));
    }
  }

  // ---------------------------------------------------------------------
  // Validation & utils
  // ---------------------------------------------------------------------

  /**
   * Returns a canonical, validated key (lower-kebab-case; digits; '-' and '.').
   *
   * @param key input key
   * @return canonical key
   * @throws IllegalArgumentException on invalid input
   */
  public static String canonicalKey(String key) {
    String k = safeOrNull(key);
    if (k == null) {
      throw new IllegalArgumentException("Header key must be non-empty");
    }
    for (int i = 0; i < k.length(); i++) {
      char c = k.charAt(i);
      boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
      if (!ok) {
        throw new IllegalArgumentException(
            "Invalid header key '"
                + key
                + "' at index "
                + i
                + " (only lowercase letters, digits, '-' and '.' are allowed)");
      }
    }
    return k;
  }

  /** Normalizes a key (trim + lower) or returns {@code null} if empty. */
  private static String safeOrNull(String key) {
    if (key == null) {
      return null;
    }
    String trimmed = key.trim().toLowerCase(Locale.ROOT);
    return trimmed.isEmpty() ? null : trimmed;
  }

  /** Validates header value size against {@link #MAX_HEADER_VALUE_BYTES}. */
  private static void validateSize(byte[] value) {
    if (value == null) {
      return;
    }
    if (value.length > MAX_HEADER_VALUE_BYTES) {
      throw new IllegalArgumentException(
          "Header value exceeds " + MAX_HEADER_VALUE_BYTES + " bytes");
    }
  }
}
