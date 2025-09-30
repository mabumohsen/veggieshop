package io.veggieshop.platform.http.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enterprise-grade request/correlation ID filter for Servlet applications (VT-friendly).
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Extracts {@code X-Request-Id} from the request (or generates one).
 *   <li>Resolves correlation ID from a configurable header (default {@code X-Correlation-Id}); if
 *       missing, optionally generates a new value or falls back to the request ID.
 *   <li>Publishes both identifiers into the {@link MDC} and echoes them on the response.
 *   <li>Guarantees strict MDC cleanup to avoid leakage across (virtual) threads.
 * </ul>
 *
 * <p>Thread-safety: stateless and thus thread-safe. This filter is intended to run early in the
 * chain to make IDs available for subsequent components (PII guard, tenancy, tracing...).
 */
@Order(CorrelationIdFilter.ORDER)
public final class CorrelationIdFilter extends OncePerRequestFilter {

  /** Run before PII guard and tenant filters. */
  public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 10;

  /** Canonical request ID header & MDC keys (stable across services). */
  public static final String HEADER_REQUEST_ID = "X-Request-Id";

  public static final String DEFAULT_CORRELATION_HEADER = "X-Correlation-Id";
  public static final String MDC_REQUEST_ID = "requestId";
  public static final String MDC_CORRELATION_ID = "correlationId";

  /** Request attributes (available to downstream handlers). */
  public static final String REQUEST_ATTR_REQUEST_ID =
      CorrelationIdFilter.class.getName() + ".REQUEST_ID";

  public static final String REQUEST_ATTR_CORRELATION_ID =
      CorrelationIdFilter.class.getName() + ".CORRELATION_ID";

  /** Correlation ID generator options. */
  public enum Generator {
    UUID_V4,
    ULID
  }

  // ---------------- Configuration (immutable) ----------------

  private final String correlationHeader;
  private final boolean generateIfMissing;
  private final Generator generator;
  private final String mdcCorrelationKey;

  /**
   * Creates a filter with sane defaults.
   *
   * <ul>
   *   <li>{@code correlationHeader = X-Correlation-Id}
   *   <li>{@code generateIfMissing = true}
   *   <li>{@code generator = ULID}
   *   <li>{@code mdcCorrelationKey = "correlationId"}
   * </ul>
   */
  public CorrelationIdFilter() {
    this(DEFAULT_CORRELATION_HEADER, true, Generator.ULID, MDC_CORRELATION_ID);
  }

  /**
   * Convenience constructor for auto-config (generator provided by name).
   *
   * @param correlationHeader header name to read/write correlation IDs from/to
   * @param generateIfMissing whether to generate a correlation ID when missing
   * @param generatorName {@link Generator#name()} value; falls back to {@code ULID} on invalid name
   * @param mdcCorrelationKey additional MDC key to mirror {@link #MDC_CORRELATION_ID} into
   */
  public CorrelationIdFilter(
      String correlationHeader,
      boolean generateIfMissing,
      String generatorName,
      String mdcCorrelationKey) {
    this(correlationHeader, generateIfMissing, parseGenerator(generatorName), mdcCorrelationKey);
  }

  /**
   * Primary constructor.
   *
   * @param correlationHeader header name to read/write correlation IDs from/to
   * @param generateIfMissing whether to generate a correlation ID when missing
   * @param generator generator strategy
   * @param mdcCorrelationKey additional MDC key to mirror {@link #MDC_CORRELATION_ID} into
   */
  public CorrelationIdFilter(
      String correlationHeader,
      boolean generateIfMissing,
      Generator generator,
      String mdcCorrelationKey) {
    this.correlationHeader =
        (correlationHeader == null || correlationHeader.isBlank())
            ? DEFAULT_CORRELATION_HEADER
            : correlationHeader.trim();
    this.generateIfMissing = generateIfMissing;
    this.generator = (generator == null ? Generator.ULID : generator);
    this.mdcCorrelationKey =
        (mdcCorrelationKey == null || mdcCorrelationKey.isBlank())
            ? MDC_CORRELATION_ID
            : mdcCorrelationKey.trim();
  }

  // ---------------- Filter logic ----------------

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    // 1) Resolve request id
    String incomingReqId = firstHeaderValue(request.getHeader(HEADER_REQUEST_ID));
    String requestId = normalizeOrGenerate(incomingReqId);

    // 2) Resolve correlation id
    String incomingCorr = firstHeaderValue(request.getHeader(this.correlationHeader));
    String correlationId = normalizeOrNull(incomingCorr);
    if (correlationId == null) {
      correlationId = generateIfMissing ? generateCorrelation() : requestId;
    }

    // 3) Publish to MDC + request attrs
    MDC.put(MDC_REQUEST_ID, requestId);
    MDC.put(MDC_CORRELATION_ID, correlationId);
    if (!MDC_CORRELATION_ID.equals(mdcCorrelationKey)) {
      MDC.put(mdcCorrelationKey, correlationId); // optional extra key
    }
    request.setAttribute(REQUEST_ATTR_REQUEST_ID, requestId);
    request.setAttribute(REQUEST_ATTR_CORRELATION_ID, correlationId);

    // 4) Echo headers back
    response.setHeader(HEADER_REQUEST_ID, requestId);
    response.setHeader(this.correlationHeader, correlationId);
    // If a custom header is used, also set the standard header for interoperability
    if (!DEFAULT_CORRELATION_HEADER.equalsIgnoreCase(this.correlationHeader)) {
      response.setHeader(DEFAULT_CORRELATION_HEADER, correlationId);
    }

    try {
      chain.doFilter(request, response);
    } finally {
      // Strict cleanup
      request.removeAttribute(REQUEST_ATTR_REQUEST_ID);
      request.removeAttribute(REQUEST_ATTR_CORRELATION_ID);
      MDC.remove(MDC_REQUEST_ID);
      MDC.remove(MDC_CORRELATION_ID);
      if (!MDC_CORRELATION_ID.equals(mdcCorrelationKey)) {
        MDC.remove(mdcCorrelationKey);
      }
    }
  }

  /** Preserve correlation on error dispatch. */
  @Override
  protected boolean shouldNotFilterErrorDispatch() {
    return false;
  }

  // ---------------- Helpers ----------------

  /** Returns the first token before a comma (proxies may join multiple values). */
  private static String firstHeaderValue(String raw) {
    if (raw == null) {
      return null;
    }
    int comma = raw.indexOf(',');
    return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
  }

  /**
   * Validates an incoming ID; returns it if safe, otherwise {@code null}. Allowed charset: {@code
   * [A-Za-z0-9._-]}, length {@code 1..128}.
   */
  private static String normalizeOrNull(String raw) {
    if (raw == null) {
      return null;
    }
    String s = raw.trim();
    if (s.isEmpty() || s.length() > 128) {
      return null;
    }
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean ok =
          (c >= 'A' && c <= 'Z')
              || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9')
              || c == '.'
              || c == '_'
              || c == '-';
      if (!ok) {
        return null;
      }
    }
    return s;
  }

  /** Validates an incoming ID or generates a 32-hex request ID (lowercase). */
  private static String normalizeOrGenerate(String raw) {
    String s = normalizeOrNull(raw);
    return (s != null ? s : generateRequestId());
  }

  private static String generateRequestId() {
    return UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
  }

  private String generateCorrelation() {
    return (generator == Generator.ULID) ? generateUlid() : generateRequestId();
  }

  // Minimal ULID generator (26 Crockford Base32 chars; timestamp ms + 80-bit randomness).
  private static final char[] CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
  private static final SecureRandom RNG = new SecureRandom();

  private static String generateUlid() {
    long time = Instant.now().toEpochMilli(); // 48 bits used
    byte[] rand = new byte[10]; // 80 bits
    RNG.nextBytes(rand);

    // Build 128-bit buffer: 48-bit time (ms) + 80-bit randomness
    byte[] data = new byte[16];
    // time -> first 6 bytes
    data[0] = (byte) (time >>> 40);
    data[1] = (byte) (time >>> 32);
    data[2] = (byte) (time >>> 24);
    data[3] = (byte) (time >>> 16);
    data[4] = (byte) (time >>> 8);
    data[5] = (byte) (time);
    // randomness -> last 10 bytes
    System.arraycopy(rand, 0, data, 6, 10);

    // Encode 128 bits -> 26 chars (5 bits per char, with some leading zeros)
    StringBuilder out = new StringBuilder(26);
    int bits = 0;
    int bitBuffer = 0;
    int written = 0;

    for (int i = 0; i < data.length && written < 26; i++) {
      bitBuffer = (bitBuffer << 8) | (data[i] & 0xFF);
      bits += 8;
      while (bits >= 5 && written < 26) {
        int idx = (bitBuffer >>> (bits - 5)) & 0x1F;
        bits -= 5;
        out.append(CROCKFORD32[idx]);
        written++;
      }
    }
    // Pad if needed
    while (written < 26) {
      out.append('0');
      written++;
    }
    return out.toString();
  }

  private static Generator parseGenerator(String name) {
    try {
      return name == null ? Generator.ULID : Generator.valueOf(name);
    } catch (IllegalArgumentException ex) {
      return Generator.ULID;
    }
  }
}
