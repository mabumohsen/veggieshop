package io.veggieshop.platform.domain.audit;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/**
 * AuditHash
 *
 * <p>Enterprise-grade, framework-agnostic content hash used for audit chaining ({@code
 * prevHash/hash}) as specified in VeggieShop PRD v2.0. This value object:
 *
 * <ul>
 *   <li>Uses a <strong>versioned domain separator</strong> to prevent cross-protocol collisions.
 *   <li>Defaults to <strong>SHA-256</strong> (stable, FIPS-acceptable in many environments).
 *   <li>Provides <strong>deterministic chaining</strong> over {@code prevHash || payload}.
 *   <li>Exposes safe factory/parse methods and immutable, constant-time equality.
 *   <li>String form: {@code sha256:<base64url_nopad>} (mirrors PRD header style, e.g. schema
 *       fingerprints).
 * </ul>
 *
 * <h3>Canonical hashing and chaining</h3>
 *
 * <pre>{@code
 * // Compute a hash for a canonical payload (caller is responsible for canonicalization)
 * AuditHash h1 = AuditHash.compute(payloadBytes);
 *
 * // Chain with previous hash (prevHash || payload) under a domain separator
 * AuditHash h2 = AuditHash.computeChained(h1, nextPayloadBytes);
 *
 * // Verification
 * boolean ok = AuditHash.verifyChain(h1, nextPayloadBytes, h2);
 * }</pre>
 *
 * <p><b>IMPORTANT:</b> Callers must supply a stable, canonical byte representation of the record
 * (e.g., canonical JSON: sorted keys, normalized numbers/whitespace/encodings). This class does not
 * perform canonicalization.
 */
public final class AuditHash {

  // --------------------------
  // Algorithm & Encoding
  // --------------------------

  /** Supported algorithms. Extend carefully (ensure deterministic length and availability). */
  public enum Algorithm {
    SHA_256("sha256", "SHA-256", 32);

    private final String id; // canonical id in string form
    private final String jcaName; // JCA algorithm name
    private final int lengthBytes;

    Algorithm(String id, String jcaName, int lengthBytes) {
      this.id = id;
      this.jcaName = jcaName;
      this.lengthBytes = lengthBytes;
    }

    /** Canonical identifier used in string form (e.g., {@code sha256}). */
    public String id() {
      return id;
    }

    /** JCA algorithm name (e.g., {@code SHA-256}). */
    public String jcaName() {
      return jcaName;
    }

    /** Digest length in bytes for this algorithm. */
    public int lengthBytes() {
      return lengthBytes;
    }

    /** Parses an algorithm by its canonical id (case-insensitive). */
    public static Algorithm byId(String raw) {
      String norm = Objects.requireNonNull(raw, "algorithm id").trim().toLowerCase(Locale.ROOT);
      for (Algorithm a : values()) {
        if (a.id.equals(norm)) {
          return a;
        }
      }
      throw new IllegalArgumentException("Unsupported algorithm id: " + raw);
    }
  }

  /** Default algorithm for VeggieShop audit chain. */
  public static final Algorithm DEFAULT_ALGORITHM = Algorithm.SHA_256;

  /** Domain separator protects against cross-use collisions (versioned). */
  private static final byte[] DOMAIN_SEP = "veggieshop.audit.v1".getBytes(StandardCharsets.UTF_8);

  private static final Base64.Encoder B64_URL_NOPAD_ENC = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64_URL_DEC = Base64.getUrlDecoder();

  // --------------------------
  // State
  // --------------------------

  private final Algorithm algorithm;
  private final byte[] bytes; // immutable copy; exact length per algorithm

  private AuditHash(Algorithm algorithm, byte[] bytes) {
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
    this.bytes = validateAndCopy(algorithm, bytes);
  }

  // --------------------------
  // Factories
  // --------------------------

  /** Construct from raw bytes (copied). */
  public static AuditHash ofBytes(byte[] bytes) {
    return new AuditHash(DEFAULT_ALGORITHM, bytes);
  }

  /** Construct from raw bytes with explicit algorithm (copied). */
  public static AuditHash ofBytes(Algorithm algorithm, byte[] bytes) {
    return new AuditHash(Objects.requireNonNull(algorithm, "algorithm"), bytes);
  }

  /** Construct from a hex string (no {@code 0x} prefix). */
  public static AuditHash ofHex(String hex) {
    return ofBytes(DEFAULT_ALGORITHM, hexToBytes(hex));
  }

  /** Construct from a base64url (no padding) string. */
  public static AuditHash ofBase64Url(String base64Url) {
    try {
      return ofBytes(
          DEFAULT_ALGORITHM, B64_URL_DEC.decode(requireNonBlank(base64Url, "base64Url")));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64url content", e);
    }
  }

  /**
   * Parses a flexible textual form.
   *
   * <ul>
   *   <li>{@code sha256:<base64url_nopad>}
   *   <li>{@code sha256:<hex>}
   * </ul>
   */
  public static AuditHash parse(String text) {
    String s = requireNonBlank(text, "text").trim();
    int idx = s.indexOf(':');
    if (idx <= 0 || idx == s.length() - 1) {
      throw new IllegalArgumentException("Invalid format: expected 'algo:value'");
    }
    Algorithm algo = Algorithm.byId(s.substring(0, idx));
    String data = s.substring(idx + 1);
    // Heuristic: hex if only [0-9a-fA-F] and even length; else base64url
    if (isLikelyHex(data)) {
      return ofBytes(algo, hexToBytes(data));
    } else {
      try {
        return ofBytes(algo, B64_URL_DEC.decode(data));
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Invalid encoded value (neither hex nor base64url)", e);
      }
    }
  }

  // --------------------------
  // Compute / Chain
  // --------------------------

  /** Compute a hash of {@code DOMAIN_SEP || 0x00 || payload}. */
  public static AuditHash compute(byte[] payload) {
    Objects.requireNonNull(payload, "payload");
    return compute(DEFAULT_ALGORITHM, payload);
  }

  /** Compute a hash of {@code DOMAIN_SEP || 0x00 || payload} with explicit algorithm. */
  public static AuditHash compute(Algorithm algorithm, byte[] payload) {
    Objects.requireNonNull(payload, "payload");
    MessageDigest md = newDigest(algorithm);
    md.update(DOMAIN_SEP);
    md.update((byte) 0x00);
    md.update(payload);
    return new AuditHash(algorithm, md.digest());
  }

  /**
   * Compute a chained hash of {@code DOMAIN_SEP || 0x01 || prevHash || payload}.
   *
   * <p>If {@code prev} is {@code null}, this behaves like {@link #compute(byte[])}.
   */
  public static AuditHash computeChained(AuditHash prev, byte[] payload) {
    Objects.requireNonNull(payload, "payload");
    MessageDigest md = newDigest(DEFAULT_ALGORITHM);
    md.update(DOMAIN_SEP);
    md.update((byte) 0x01);
    if (prev != null) {
      // Cross-algo chaining not allowed for determinism
      if (prev.algorithm != DEFAULT_ALGORITHM) {
        throw new IllegalArgumentException(
            "Algorithm mismatch in chain: expected " + DEFAULT_ALGORITHM.id());
      }
      md.update(prev.bytes);
    }
    md.update(payload);
    return new AuditHash(DEFAULT_ALGORITHM, md.digest());
  }

  /** Verify that {@code candidate} equals {@code computeChained(prev, payload)}. */
  public static boolean verifyChain(AuditHash prev, byte[] payload, AuditHash candidate) {
    Objects.requireNonNull(candidate, "candidate");
    AuditHash computed = computeChained(prev, payload);
    return candidate.equals(computed);
  }

  // --------------------------
  // Accessors
  // --------------------------

  /** Returns the algorithm used to compute this hash. */
  public Algorithm algorithm() {
    return algorithm;
  }

  /** Returns a defensive copy of the raw hash bytes. */
  public byte[] toByteArray() {
    return bytes.clone();
  }

  /** Base64url (no padding) representation of the raw bytes. */
  public String toBase64Url() {
    return B64_URL_NOPAD_ENC.encodeToString(bytes);
  }

  /** Hex representation (lowercase). */
  public String toHex() {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
      sb.append(Character.forDigit(b & 0xF, 16));
    }
    return sb.toString();
  }

  /** String form: {@code <algo>:<base64url_nopad>} (stable and URL-safe). */
  @Override
  public String toString() {
    return algorithm.id() + ":" + toBase64Url();
  }

  // --------------------------
  // Equality & HashCode
  // --------------------------

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof AuditHash that)) {
      return false;
    }
    if (this.algorithm != that.algorithm) {
      return false;
    }
    // Constant-time comparison on bytes
    return MessageDigest.isEqual(this.bytes, that.bytes);
  }

  @Override
  public int hashCode() {
    // Mix algo ordinal with first 4 bytes for decent distribution without exposing bytes fully
    int h = 31 * algorithm.ordinal();
    if (bytes.length >= 4) {
      h = 31 * h + ByteBuffer.wrap(bytes, 0, 4).getInt();
    } else {
      for (byte b : bytes) {
        h = 31 * h + b;
      }
    }
    return h;
  }

  // --------------------------
  // Helpers
  // --------------------------

  private static byte[] validateAndCopy(Algorithm algorithm, byte[] in) {
    Objects.requireNonNull(in, "bytes");
    if (in.length != algorithm.lengthBytes()) {
      throw new IllegalArgumentException(
          "Invalid hash length for "
              + algorithm.id()
              + ": expected "
              + algorithm.lengthBytes()
              + " bytes, got "
              + in.length);
    }
    return in.clone();
  }

  private static MessageDigest newDigest(Algorithm algorithm) {
    try {
      return MessageDigest.getInstance(algorithm.jcaName());
    } catch (NoSuchAlgorithmException e) {
      // Should never happen on a compliant JRE
      throw new IllegalStateException("JCA algorithm not available: " + algorithm.jcaName(), e);
    }
  }

  private static String requireNonBlank(String s, String what) {
    if (s == null || s.isBlank()) {
      throw new IllegalArgumentException(what + " must not be blank");
    }
    return s;
  }

  private static boolean isLikelyHex(String s) {
    if (s == null) {
      return false;
    }
    int len = s.length();
    if ((len & 1) == 1 || len == 0) {
      return false;
    }
    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);
      boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!hex) {
        return false;
      }
    }
    return true;
  }

  private static byte[] hexToBytes(String hex) {
    String h = requireNonBlank(hex, "hex").trim();
    if (!isLikelyHex(h)) {
      throw new IllegalArgumentException("Invalid hex string");
    }
    int len = h.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      int hi = Character.digit(h.charAt(i), 16);
      int lo = Character.digit(h.charAt(i + 1), 16);
      out[i / 2] = (byte) ((hi << 4) + lo);
    }
    return out;
  }
}
