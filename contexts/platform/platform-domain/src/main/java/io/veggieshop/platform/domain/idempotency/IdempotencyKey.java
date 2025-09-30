package io.veggieshop.platform.domain.idempotency;

import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * IdempotencyKey
 *
 * <p>Enterprise-grade value object representing an HTTP {@code Idempotency-Key} and the canonical
 * identifier used in the idempotency store. This implementation follows the PRD v2.0 guidance:
 * mutating HTTP endpoints require an {@code Idempotency-Key}; the backing store uses a PostgreSQL
 * {@code UUID} primary key composed with {@code tenant_id}.
 *
 * <h2>Design goals</h2>
 *
 * <ul>
 *   <li><b>Strong typing:</b> wraps a {@link UUID}; avoids “naked string” keys across the codebase.
 *   <li><b>Strict validation:</b> accepts only RFC&nbsp;4122 UUIDs (v1–v5), with flexible parsing
 *       of hyphenated and 32-hex formats; rejects malformed values early.
 *   <li><b>Framework-agnostic:</b> no servlet/Spring/Kafka dependencies; suitable for domain layer.
 *   <li><b>Ergonomics:</b> helpers to parse from header maps, generate secure random keys, and
 *       convert to bytes.
 * </ul>
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * // From an HTTP header value:
 * IdempotencyKey key = IdempotencyKey.parse(headerValue);
 *
 * // From headers map (case-insensitive):
 * Optional<IdempotencyKey> maybe = IdempotencyKey.fromHeaders(requestHeaders);
 *
 * // Generate on server (e.g., internal retries or tests):
 * IdempotencyKey key = IdempotencyKey.random();
 *
 * // Persist or log:
 * UUID uuid = key.asUuid();
 * String header = key.toHeaderValue(); // canonical lower-case UUID with hyphens
 * byte[] bytes = key.toBytes();        // 16-byte representation
 * }</pre>
 */
public final class IdempotencyKey implements Comparable<IdempotencyKey>, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /** Canonical HTTP header name (per PRD §10). */
  public static final String REQUEST_HEADER = "Idempotency-Key";

  /** Tolerated header aliases (case-insensitive) for partner/legacy integrations. */
  private static final List<String> HEADER_ALIASES =
      List.of(REQUEST_HEADER, "idempotency-key", "IDEMPOTENCY-KEY");

  /** Canonical hyphenated UUID pattern (enforces version and IETF variant nibble). */
  private static final Pattern UUID_CANONICAL =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
              + "[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");

  /** 32 hex characters (no hyphens). Version/variant are validated post parse. */
  private static final Pattern UUID_HEX32 = Pattern.compile("^[0-9a-fA-F]{32}$");

  private final UUID value; // immutable, never null

  private IdempotencyKey(UUID value) {
    this.value = Objects.requireNonNull(value, "value");
    // Enforce IETF variant (RFC 4122); version 1–5 allowed.
    if (value.variant() != 2 /* IETF RFC 4122 */) {
      throw new IllegalArgumentException(
          "Idempotency key must be an RFC 4122 UUID (IETF variant).");
    }
    int v = value.version();
    if (v < 1 || v > 5) {
      throw new IllegalArgumentException("Unsupported UUID version: " + v + " (expected 1–5).");
    }
  }

  // -------------------------------------------------------------------------------------
  // Factory methods
  // -------------------------------------------------------------------------------------

  /** Create from an existing UUID (validated). */
  public static IdempotencyKey of(UUID uuid) {
    return new IdempotencyKey(uuid);
  }

  /**
   * Parse from a string. Accepts:
   *
   * <ul>
   *   <li>Canonical UUID (hyphenated), e.g., {@code 123e4567-e89b-12d3-a456-426614174000}
   *   <li>32 hex characters (no hyphens); will be normalized to canonical form
   * </ul>
   *
   * @throws IllegalArgumentException if the value is null/blank or not a valid RFC 4122 UUID
   */
  public static IdempotencyKey parse(String raw) {
    String s = normalize(raw);
    if (s == null) {
      throw new IllegalArgumentException("Idempotency key is required.");
    }
    final UUID uuid;
    if (UUID_CANONICAL.matcher(s).matches()) {
      uuid = UUID.fromString(s);
    } else if (UUID_HEX32.matcher(s).matches()) {
      uuid = uuidFromHex32(s);
    } else {
      // Try UUID.fromString as a last attempt (covers mixed-case or minor variations).
      try {
        uuid = UUID.fromString(s);
      } catch (RuntimeException e) {
        throw new IllegalArgumentException("Invalid idempotency key format.", e);
      }
    }
    return new IdempotencyKey(uuid);
  }

  /** Try parse without throwing. Returns empty on invalid/blank input. */
  public static Optional<IdempotencyKey> tryParse(String raw) {
    try {
      return Optional.of(parse(raw));
    } catch (IllegalArgumentException ex) {
      return Optional.empty();
    }
  }

  /**
   * Resolve from a case-insensitive headers map, checking common aliases. Returns empty if absent
   * or invalid.
   */
  public static Optional<IdempotencyKey> fromHeaders(Map<String, ?> headers) {
    if (headers == null || headers.isEmpty()) {
      return Optional.empty();
    }
    Map<String, Object> ci = new HashMap<>(headers.size());
    for (Map.Entry<String, ?> e : headers.entrySet()) {
      if (e.getKey() != null) {
        ci.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
      }
    }
    for (String alias : HEADER_ALIASES) {
      Object v = ci.get(alias.toLowerCase(Locale.ROOT));
      if (v != null) {
        Optional<IdempotencyKey> parsed = tryParse(String.valueOf(v));
        if (parsed.isPresent()) {
          return parsed;
        }
      }
    }
    return Optional.empty();
  }

  /** Generate a new secure-random UUID-based key (RFC 4122 v4). */
  public static IdempotencyKey random() {
    return new IdempotencyKey(UUID.randomUUID());
  }

  // -------------------------------------------------------------------------------------
  // Accessors
  // -------------------------------------------------------------------------------------

  /** Canonical UUID representation (lower-case, hyphenated). */
  public String toHeaderValue() {
    return value.toString();
  }

  /** Raw UUID value. */
  public UUID asUuid() {
    return value;
  }

  /** 16-byte array representation (big-endian per {@link UUID}). */
  public byte[] toBytes() {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(value.getMostSignificantBits());
    buf.putLong(value.getLeastSignificantBits());
    return buf.array();
  }

  // -------------------------------------------------------------------------------------
  // Object contract
  // -------------------------------------------------------------------------------------

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof IdempotencyKey that)) {
      return false;
    }
    return value.equals(that.value);
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public String toString() {
    // Safe to log: not PII, but keep concise & canonical.
    return value.toString();
  }

  @Override
  public int compareTo(IdempotencyKey o) {
    // Compare lexicographically by canonical string; stable and human-friendly.
    return this.toHeaderValue().compareTo(o.toHeaderValue());
  }

  // -------------------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------------------

  private static String normalize(String s) {
    if (s == null) {
      return null;
    }
    String t = s.trim();
    return (t.isEmpty() || "null".equalsIgnoreCase(t)) ? null : t;
  }

  private static UUID uuidFromHex32(String hex32) {
    // Insert hyphens at 8-4-4-4-12 boundaries to parse canonically.
    String h = hex32.toLowerCase(Locale.ROOT);
    String canonical =
        h.substring(0, 8)
            + "-"
            + h.substring(8, 12)
            + "-"
            + h.substring(12, 16)
            + "-"
            + h.substring(16, 20)
            + "-"
            + h.substring(20);
    return UUID.fromString(canonical);
  }
}
