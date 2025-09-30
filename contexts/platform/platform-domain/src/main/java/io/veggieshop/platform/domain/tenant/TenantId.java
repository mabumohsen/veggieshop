package io.veggieshop.platform.domain.tenant;

import java.io.Serial;
import java.io.Serializable;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Enterprise-grade immutable tenant identifier.
 *
 * <p>- Lowercase ASCII letters, digits and single hyphens, 3..63 chars. <br>
 * - No leading/trailing hyphen and no consecutive "--". <br>
 * - Framework-agnostic (pure domain).
 */
public record TenantId(String value) implements Comparable<TenantId>, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /** Minimum allowed length. */
  public static final int MIN_LENGTH = 3;

  /** Maximum allowed length. */
  public static final int MAX_LENGTH = 63;

  /** Allowed characters/pattern (lowercase letters, digits, hyphen with no edge hyphens). */
  private static final Pattern ALLOWED = Pattern.compile("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$");

  /**
   * Compact canonical constructor; normalizes and validates the identifier.
   *
   * @throws NullPointerException if {@code value} is null
   * @throws IllegalArgumentException if the value violates format/length rules
   */
  public TenantId {
    Objects.requireNonNull(value, "tenantId must not be null");
    String normalized = normalize(value);
    if (!isValid(normalized)) {
      throw new IllegalArgumentException(
          "Invalid tenantId: '%s' (must match %s, length %d..%d, no \"--\")"
              .formatted(value, ALLOWED.pattern(), MIN_LENGTH, MAX_LENGTH));
    }
    value = normalized;
  }

  /**
   * Factory method that validates and returns a new {@link TenantId}.
   *
   * @param raw raw tenant id string
   * @return a validated {@link TenantId}
   * @throws NullPointerException if {@code raw} is null
   * @throws IllegalArgumentException if {@code raw} is invalid
   */
  public static TenantId of(String raw) {
    return new TenantId(raw);
  }

  /**
   * Lenient parser that returns {@link Optional#empty()} on invalid input.
   *
   * @param raw raw tenant id string
   * @return optional of validated {@link TenantId}, or empty if invalid/blank
   */
  public static Optional<TenantId> tryParse(String raw) {
    if (raw == null) {
      return Optional.empty();
    }
    String n = normalize(raw);
    return isValid(n) ? Optional.of(new TenantId(n)) : Optional.empty();
  }

  /**
   * Validates a normalized candidate (lowercasing/trim happen in {@link #normalize(String)}).
   *
   * @param candidate normalized candidate
   * @return true if valid per length/pattern and without {@code "--"}
   */
  public static boolean isValid(String candidate) {
    if (candidate == null) {
      return false;
    }
    int len = candidate.length();
    if (len < MIN_LENGTH || len > MAX_LENGTH) {
      return false;
    }
    if (!ALLOWED.matcher(candidate).matches()) {
      return false;
    }
    if (candidate.contains("--")) {
      return false;
    }
    return true;
  }

  /**
   * Obfuscated form for logs/metrics; hides middle characters.
   *
   * @return obfuscated representation
   */
  public String obfuscated() {
    int len = value.length();
    if (len <= 5) {
      return "***";
    }
    return value.substring(0, 3) + "…" + value.substring(len - 2);
  }

  /**
   * Normalizes input by trimming and lowercasing using {@link Locale#ROOT}.
   *
   * @param raw raw value
   * @return normalized value
   */
  private static String normalize(String raw) {
    return raw.trim().toLowerCase(Locale.ROOT);
  }

  /**
   * Natural ordering by canonical value (lexicographic).
   *
   * @param other other id
   * @return comparison result
   */
  @Override
  public int compareTo(TenantId other) {
    return this.value.compareTo(other.value);
  }

  /**
   * Canonical string form of the identifier.
   *
   * @return canonical value
   */
  @Override
  public String toString() {
    return value;
  }
}
