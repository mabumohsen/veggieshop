package io.veggieshop.platform.application.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HashingService
 *
 * <p>Plain utility (framework-agnostic) offering:
 *
 * <ul>
 *   <li>Message digests (byte[], String, streaming InputStream)
 *   <li>HMAC (bytes) with hex/Base64 helpers
 *   <li>Canonical-JSON hashing for stable signatures
 *   <li>Idempotency request hashing and audit-chain hashing
 *   <li>Constant-time equality and fingerprint helpers
 * </ul>
 *
 * <p>Thread-safe via per-algorithm {@link ThreadLocal} {@link MessageDigest} instances.
 */
public final class HashingService {

  private static final int STREAM_BUFFER = 16 * 1024;

  /** Canonical JSON for stable hashing (sorted keys, no pretty-print). */
  private static final ObjectMapper CANONICAL_JSON =
      new ObjectMapper()
          .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
          .disable(SerializationFeature.INDENT_OUTPUT);

  private final EnumMap<HashAlgorithm, ThreadLocal<MessageDigest>> digests =
      new EnumMap<>(HashAlgorithm.class);

  /** Creates a new service with JCA digests prepared per algorithm. */
  public HashingService() {
    for (HashAlgorithm alg : HashAlgorithm.values()) {
      digests.put(alg, ThreadLocal.withInitial(() -> newDigest(alg.jcaName)));
    }
  }

  // -------- Digests --------

  /**
   * Computes a digest over the given bytes.
   *
   * @param input bytes to hash
   * @param alg hashing algorithm
   * @return digest bytes
   */
  public byte[] digest(@NotNull byte[] input, @NotNull HashAlgorithm alg) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(alg, "alg");
    MessageDigest md = digests.get(alg).get();
    md.reset();
    return md.digest(input);
  }

  /**
   * Computes a digest over a normalized UTF-8 string.
   *
   * @param input string to hash (NFKC normalized)
   * @param alg hashing algorithm
   * @return digest bytes
   */
  public byte[] digest(@NotNull String input, @NotNull HashAlgorithm alg) {
    Objects.requireNonNull(input, "input");
    String norm = Normalizer.normalize(input, Normalizer.Form.NFKC);
    return digest(norm.getBytes(StandardCharsets.UTF_8), alg);
  }

  /**
   * Streams an {@link InputStream} through a digest.
   *
   * @param in input stream (will be fully read; caller closes if needed)
   * @param alg hashing algorithm
   * @return digest bytes
   * @throws IOException if reading fails
   */
  public byte[] digest(@NotNull InputStream in, @NotNull HashAlgorithm alg) throws IOException {
    Objects.requireNonNull(in, "in");
    MessageDigest md = digests.get(alg).get();
    md.reset();
    try (DigestInputStream dis = new DigestInputStream(in, md)) {
      byte[] buf = new byte[STREAM_BUFFER];
      while (dis.read(buf) != -1) {
        // DigestInputStream updates md
      }
    }
    return md.digest();
  }

  /**
   * Computes a hex fingerprint string with a leading scheme (e.g., {@code sha256:abc123...}).
   *
   * @param input bytes to hash
   * @param alg hashing algorithm
   * @return scheme-prefixed hex string
   */
  public String fingerprintHex(@NotNull byte[] input, @NotNull HashAlgorithm alg) {
    return alg.scheme + ":" + HexFormat.of().formatHex(digest(input, alg));
  }

  /**
   * Computes a Base64(Base64url) encoded digest.
   *
   * @param input bytes to hash
   * @param alg hashing algorithm
   * @param urlSafe whether to use URL-safe Base64 without padding
   * @return encoded digest string
   */
  public String digestBase64(@NotNull byte[] input, @NotNull HashAlgorithm alg, boolean urlSafe) {
    byte[] d = digest(input, alg);
    return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder())
        .encodeToString(d);
  }

  // -------- HMAC --------

  /**
   * Computes an HMAC over {@code message} with {@code secretKey}.
   *
   * @param secretKey secret key bytes
   * @param message message bytes
   * @param alg HMAC algorithm
   * @return MAC bytes
   */
  public byte[] hmac(
      @NotNull byte[] secretKey, @NotNull byte[] message, @NotNull HmacAlgorithm alg) {
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

  /**
   * Computes an HMAC and returns the hex string.
   *
   * @param secretKey secret key bytes
   * @param message message bytes
   * @param alg HMAC algorithm
   * @return hex-encoded MAC
   */
  public String hmacHex(
      @NotNull byte[] secretKey, @NotNull byte[] message, @NotNull HmacAlgorithm alg) {
    return HexFormat.of().formatHex(hmac(secretKey, message, alg));
  }

  /**
   * Computes an HMAC and returns Base64(Base64url) string.
   *
   * @param secretKey secret key bytes
   * @param message message bytes
   * @param alg HMAC algorithm
   * @param urlSafe whether to use URL-safe Base64 without padding
   * @return encoded MAC
   */
  public String hmacBase64(
      @NotNull byte[] secretKey,
      @NotNull byte[] message,
      @NotNull HmacAlgorithm alg,
      boolean urlSafe) {
    byte[] mac = hmac(secretKey, message, alg);
    return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder())
        .encodeToString(mac);
  }

  // -------- Canonical JSON hashing --------

  /**
   * Serializes {@code value} as canonical JSON (stable key order) and digests the bytes.
   *
   * @param value arbitrary POJO/Map/List
   * @param alg hashing algorithm
   * @return digest bytes
   */
  public byte[] digestCanonicalJson(@NotNull Object value, @NotNull HashAlgorithm alg) {
    try {
      byte[] canonical = CANONICAL_JSON.writeValueAsBytes(value);
      return digest(canonical, alg);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Failed to serialize value to canonical JSON", e);
    }
  }

  // -------- Request hash (idempotency) --------

  /**
   * Computes a stable request hash for idempotency by framing: {@code
   * [method][path][sorted-headers-as-canonical-json][body]}.
   *
   * <p>Instead of relying on {@code Map.toString()} (undefined order), headers are serialized as
   * canonical JSON with case-insensitive key sorting and NFKC value normalization.
   *
   * @param httpMethod HTTP method (e.g., POST)
   * @param path request path (normalized)
   * @param selectedHeaders selected headers to include; order is normalized
   * @param body request body bytes
   * @param alg hashing algorithm
   * @return digest bytes
   */
  public byte[] computeRequestHash(
      @NotBlank String httpMethod,
      @NotBlank String path,
      @NotNull Map<String, String> selectedHeaders,
      @NotNull byte[] body,
      @NotNull HashAlgorithm alg) {

    // Canonicalize + sort headers
    Map<String, String> canonicalHeaders = new LinkedHashMap<>();
    selectedHeaders.entrySet().stream()
        .sorted(Comparator.comparing(e -> e.getKey().toLowerCase()))
        .forEach(
            e -> {
              canonicalHeaders.put(
                  e.getKey().toLowerCase(),
                  e.getValue() == null
                      ? ""
                      : Normalizer.normalize(e.getValue(), Normalizer.Form.NFKC));
            });

    byte[] methodBytes =
        Normalizer.normalize(httpMethod.trim(), Normalizer.Form.NFKC)
            .getBytes(StandardCharsets.UTF_8);
    byte[] pathBytes =
        Normalizer.normalize(path, Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);

    // Use canonical JSON for headers to get a stable byte representation.
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

  /**
   * Chains an audit record onto the previous hash: {@code H(prev || payload)}.
   *
   * @param previousHashOrEmpty previous hash bytes (or empty array)
   * @param payload payload bytes
   * @param alg hashing algorithm
   * @return new chain hash
   */
  public byte[] chainAudit(
      @NotNull byte[] previousHashOrEmpty, @NotNull byte[] payload, @NotNull HashAlgorithm alg) {
    return digest(frame(previousHashOrEmpty, payload), alg);
  }

  /**
   * Chains an audit record using a previous hex hash string.
   *
   * @param previousHashHexOrEmpty previous hex hash (or empty string)
   * @param payload payload bytes
   * @param alg hashing algorithm
   * @return new chain hash
   */
  public byte[] chainAuditHex(
      @NotNull String previousHashHexOrEmpty, @NotNull byte[] payload, @NotNull HashAlgorithm alg) {
    byte[] prev =
        previousHashHexOrEmpty.isBlank()
            ? new byte[0]
            : HexFormat.of().parseHex(previousHashHexOrEmpty);
    return chainAudit(prev, payload, alg);
  }

  // -------- Utilities --------

  /**
   * Constant-time equality for two equal-length byte arrays.
   *
   * @param a first array
   * @param b second array
   * @return true if equal, false otherwise
   */
  public boolean constantTimeEquals(@NotNull byte[] a, @NotNull byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    int r = 0;
    for (int i = 0; i < a.length; i++) {
      r |= (a[i] ^ b[i]);
    }
    return r == 0;
  }

  /**
   * Parses a {@code scheme:hex} fingerprint into raw bytes and validates the scheme.
   *
   * @param fingerprint fingerprint string (e.g., {@code sha256:deadbeef...})
   * @param expectedAlg expected hashing algorithm
   * @return raw digest bytes
   */
  public byte[] parseFingerprint(@NotBlank String fingerprint, @NotNull HashAlgorithm expectedAlg) {
    int idx = fingerprint.indexOf(':');
    if (idx <= 0) {
      throw new IllegalArgumentException("Invalid fingerprint (missing scheme): " + fingerprint);
    }
    String scheme = fingerprint.substring(0, idx);
    if (!scheme.equalsIgnoreCase(expectedAlg.scheme)) {
      throw new IllegalArgumentException(
          "Unexpected scheme: " + scheme + " (expected " + expectedAlg.scheme + ")");
    }
    String hex = fingerprint.substring(idx + 1);
    return HexFormat.of().parseHex(hex);
  }

  /**
   * Hex-encodes the provided bytes.
   *
   * @param bytes input bytes
   * @return hex string
   */
  public String toHex(@NotNull byte[] bytes) {
    return HexFormat.of().formatHex(bytes);
  }

  /**
   * Base64/Base64url-encodes the provided bytes.
   *
   * @param bytes input bytes
   * @param urlSafe whether to use URL-safe Base64 without padding
   * @return encoded string
   */
  public String toBase64(@NotNull byte[] bytes, boolean urlSafe) {
    return (urlSafe ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder())
        .encodeToString(bytes);
  }

  // -------- Internals --------

  /**
   * Creates a new JCA {@link MessageDigest} instance, or throws if unavailable.
   *
   * @param jcaName algorithm name
   * @return new digest instance
   */
  private static MessageDigest newDigest(String jcaName) {
    try {
      return MessageDigest.getInstance(jcaName);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Digest algorithm not available: " + jcaName, e);
    }
  }

  /**
   * Length-prefixed framing: {@code [len(x1)][x1][len(x2)][x2]...}.
   *
   * @param parts byte chunks
   * @return framed bytes
   */
  private static byte[] frame(byte[]... parts) {
    int size = 0;
    for (byte[] p : parts) {
      size += 4 + p.length;
    }
    ByteBuffer buf = ByteBuffer.allocate(size);
    for (byte[] p : parts) {
      buf.putInt(p.length);
      buf.put(p);
    }
    return buf.array();
  }

  // -------- Enums --------

  /** Supported hashing algorithms with their schemes and JCA names. */
  public enum HashAlgorithm {
    /** SHA-256 (scheme {@code sha256}). */
    SHA_256("sha256", "SHA-256"),
    /** SHA-512/256 (scheme {@code sha512-256}). */
    SHA_512_256("sha512-256", "SHA-512/256"),
    /** SHA3-256 (scheme {@code sha3-256}). */
    SHA3_256("sha3-256", "SHA3-256");

    /** Fingerprint scheme used in strings (case-insensitive). */
    public final String scheme;

    /** JCA algorithm name. */
    public final String jcaName;

    HashAlgorithm(String scheme, String jcaName) {
      this.scheme = scheme;
      this.jcaName = jcaName;
    }
  }

  /** Supported HMAC algorithms (JCA names). */
  public enum HmacAlgorithm {
    /** HMAC using SHA-256. */
    HMAC_SHA256("HmacSHA256"),
    /** HMAC using SHA-512. */
    HMAC_SHA512("HmacSHA512");

    /** JCA algorithm name. */
    public final String jcaName;

    HmacAlgorithm(String jcaName) {
      this.jcaName = jcaName;
    }
  }
}
