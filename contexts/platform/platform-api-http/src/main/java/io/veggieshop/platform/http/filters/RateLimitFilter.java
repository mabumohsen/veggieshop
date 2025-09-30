package io.veggieshop.platform.http.filters;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Tenant-aware rate limiting filter (RFC 9239 compliant).
 *
 * <p>Features:
 *
 * <ul>
 *   <li>Token-bucket with nanosecond precision and sane defaults.
 *   <li>Composite key policy: {@code ip | tenant | header:&lt;NAME&gt; | path}.
 *   <li>Emits RFC 9239 headers: {@code RateLimit-Limit}, {@code RateLimit-Remaining}, {@code
 *       RateLimit-Reset} (and {@code Retry-After} on throttle).
 *   <li>No PII leakage: tenant is taken from {@link TenantContext} or {@code X-Tenant-Id} only.
 * </ul>
 *
 * <p>Registered via auto-configuration in the starter; no Spring stereotype here.
 */
@Order(RateLimitFilter.ORDER)
public final class RateLimitFilter extends OncePerRequestFilter {

  /** Run right after {@link TenantFilter} to ensure tenant context is present. */
  public static final int ORDER = TenantFilter.ORDER + 10;

  // RFC 9239 headers
  public static final String HDR_RATELIMIT_LIMIT = "RateLimit-Limit";
  public static final String HDR_RATELIMIT_REMAINING = "RateLimit-Remaining";
  public static final String HDR_RATELIMIT_RESET = "RateLimit-Reset";

  /** Canonical tenant header (fallback when {@link TenantContext} is not initialized). */
  public static final String HEADER_TENANT_ID = "X-Tenant-Id";

  // Key spec tokens
  private static final String KEY_IP = "ip";
  private static final String KEY_TENANT = "tenant";
  private static final String KEY_HEADER = "header:"; // e.g., header:X-API-Key
  private static final String KEY_PATH = "path";

  // Static allowlist (globally skipped)
  private static final Set<String> ALLOWLIST_EXACT = Set.of("/error", "/favicon.ico");
  private static final AntPathMatcher ANT = new AntPathMatcher();

  // ---------------- Configuration (immutable) ----------------

  private final boolean emitHeaders;
  private final List<KeyPart> keySpec;
  private final Policy defaultPolicy;
  private final LinkedHashMap<String, Policy> overrides; // path pattern -> policy
  private final int maxBuckets;
  private final Duration idleEvictAfter;

  // ---------------- State ----------------

  /** In-memory buckets keyed by composed key. */
  private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

  // ---------------- Constructors ----------------

  /**
   * Convenience constructor that uses sane defaults for {@code capacity}, {@code maxBuckets}, and
   * {@code idleEvictAfter}.
   */
  public RateLimitFilter(
      boolean emitHeaders,
      List<String> keySpecTokens,
      Policy defaultPolicy,
      Map<String, Policy> overrides) {
    this(
        emitHeaders,
        parseKeySpec(keySpecTokens),
        ensurePolicy(defaultPolicy),
        toPolicyMap(overrides),
        Integer.getInteger("veggieshop.ratelimit.maxBuckets", 200_000),
        Duration.ofSeconds(Long.getLong("veggieshop.ratelimit.idleEvictSeconds", 900)));
  }

  /** Primary constructor. */
  public RateLimitFilter(
      boolean emitHeaders,
      List<KeyPart> keySpec,
      Policy defaultPolicy,
      LinkedHashMap<String, Policy> overrides,
      int maxBuckets,
      Duration idleEvictAfter) {
    this.emitHeaders = emitHeaders;
    this.keySpec = List.copyOf(keySpec);
    this.defaultPolicy = Objects.requireNonNull(defaultPolicy, "defaultPolicy");
    this.overrides = (overrides == null ? new LinkedHashMap<>() : overrides);
    this.maxBuckets = Math.max(1, maxBuckets);
    this.idleEvictAfter = Objects.requireNonNull(idleEvictAfter, "idleEvictAfter");
  }

  /** Convenience constructor (full args) that accepts keySpec as {@code List<String>}. */
  public RateLimitFilter(
      boolean emitHeaders,
      List<String> keySpecTokens,
      Policy defaultPolicy,
      Map<String, Policy> overrides,
      int maxBuckets,
      Duration idleEvictAfter) {
    this(
        emitHeaders,
        parseKeySpec(keySpecTokens),
        ensurePolicy(defaultPolicy),
        toPolicyMap(overrides),
        Math.max(1, maxBuckets),
        Objects.requireNonNull(idleEvictAfter, "idleEvictAfter"));
  }

  // ---------------- Filter logic ----------------

  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
    // Skip CORS preflight
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())
        && request.getHeader("Access-Control-Request-Method") != null) {
      return true;
    }
    String path = request.getRequestURI();
    return path != null && ALLOWLIST_EXACT.contains(path);
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    final Policy policy = resolvePolicy(request);
    final String bucketKey = composeBucketKey(request);

    final TokenBucket bucket = buckets.computeIfAbsent(bucketKey, k -> new TokenBucket(policy));
    final ConsumeResult result = bucket.tryConsumeOne(policy);

    if (result.allowed()) {
      if (emitHeaders) {
        response.setHeader(HDR_RATELIMIT_LIMIT, policy.limitHeaderValue());
        response.setHeader(HDR_RATELIMIT_REMAINING, String.valueOf(result.remaining()));
        response.setHeader(HDR_RATELIMIT_RESET, String.valueOf(result.resetSeconds()));
      }
      pruneIfNecessary();
      chain.doFilter(request, response);
      return;
    }

    // Throttled
    if (emitHeaders) {
      response.setHeader(HDR_RATELIMIT_LIMIT, policy.limitHeaderValue());
      response.setHeader(HDR_RATELIMIT_REMAINING, "0");
      response.setHeader(HDR_RATELIMIT_RESET, String.valueOf(result.resetSeconds()));
      response.setHeader("Retry-After", String.valueOf(result.resetSeconds()));
    }
    throw VeggieException.builder(ProblemTypes.RATE_LIMITED)
        .detail("Rate limit exceeded for key '" + redact(bucketKey) + "'")
        .captureStackTrace(false)
        .build();
  }

  // ---------------- Policy & Key resolution ----------------

  private Policy resolvePolicy(HttpServletRequest req) {
    String path = Optional.ofNullable(req.getRequestURI()).orElse("");
    for (Map.Entry<String, Policy> e : overrides.entrySet()) {
      if (ANT.match(e.getKey(), path)) {
        return e.getValue();
      }
    }
    return defaultPolicy;
  }

  private String composeBucketKey(HttpServletRequest req) {
    StringBuilder sb = new StringBuilder(72);
    for (int i = 0; i < keySpec.size(); i++) {
      if (i > 0) {
        sb.append('|');
      }
      sb.append(keySpec.get(i).resolve(req));
    }
    return sb.toString();
  }

  // ---------------- Eviction ----------------

  /** Opportunistic pruning when buckets exceed the limit; removes ~10% idle entries. */
  private void pruneIfNecessary() {
    int size = buckets.size();
    if (size <= maxBuckets) {
      return;
    }

    long now = System.nanoTime();
    long idleNs = idleEvictAfter.toNanos();
    int targetRemove = Math.max(1, size / 10);
    int removed = 0;

    for (var it = buckets.entrySet().iterator(); it.hasNext() && removed < targetRemove; ) {
      var e = it.next();
      if (now - e.getValue().lastSeenNanos > idleNs) {
        it.remove();
        removed++;
      }
    }

    // Remove random entries if still above target (keeps structure bounded)
    while (removed < targetRemove && !buckets.isEmpty()) {
      int skip = ThreadLocalRandom.current().nextInt(Math.max(1, buckets.size()));
      var it = buckets.entrySet().iterator();
      for (int i = 0; i < skip && it.hasNext(); i++) {
        it.next();
      }
      if (it.hasNext()) {
        it.next();
        it.remove();
        removed++;
      } else {
        break;
      }
    }
  }

  // ---------------- Inner types ----------------

  /** Immutable token-bucket policy. */
  public static final class Policy {
    final long capacity;
    final long refillTokens;
    final long periodNanos;
    final int windowSeconds;

    /**
     * Creates a new token-bucket policy.
     *
     * @param capacity bucket capacity (&gt; 0)
     * @param refillTokens tokens added per {@code refillPeriod} (&gt; 0)
     * @param refillPeriod refill period, must be positive
     */
    public Policy(long capacity, long refillTokens, Duration refillPeriod) {
      if (capacity <= 0 || refillTokens <= 0) {
        throw new IllegalArgumentException(
            "Invalid rate-limit policy: capacity/refillTokens must be > 0");
      }
      if (refillPeriod == null || refillPeriod.isZero() || refillPeriod.isNegative()) {
        throw new IllegalArgumentException(
            "Invalid rate-limit policy: refillPeriod must be positive");
      }
      this.capacity = capacity;
      this.refillTokens = refillTokens;
      this.periodNanos = refillPeriod.toNanos();
      this.windowSeconds = Math.toIntExact(refillPeriod.toSeconds());
    }

    /** Formats the RFC 9239 RateLimit-Limit header value. */
    String limitHeaderValue() {
      return capacity + ";w=" + windowSeconds;
    }
  }

  /** Parsed key part. */
  private sealed interface KeyPart permits IpPart, TenantPart, HeaderPart, PathPart {
    String resolve(HttpServletRequest req);
  }

  private static final class IpPart implements KeyPart {
    @Override
    public String resolve(HttpServletRequest req) {
      String xff = firstToken(req.getHeader("X-Forwarded-For"));
      return (xff != null && !xff.isBlank())
          ? xff
          : Objects.toString(req.getRemoteAddr(), "ip:unknown");
    }
  }

  private static final class TenantPart implements KeyPart {
    @Override
    public String resolve(HttpServletRequest req) {
      TenantId ctx = TenantContext.currentTenantId().orElse(null);
      if (ctx != null) {
        return ctx.value();
      }
      String raw = firstToken(req.getHeader(HEADER_TENANT_ID));
      if (raw == null || raw.isBlank()) {
        // Same contract as TenantFilter
        throw VeggieException.builder(ProblemTypes.TENANT_REQUIRED)
            .detail("Missing required header: " + HEADER_TENANT_ID)
            .captureStackTrace(false)
            .build();
      }
      return raw.trim();
    }
  }

  private static final class HeaderPart implements KeyPart {
    private final String header;

    HeaderPart(String header) {
      this.header = header;
    }

    @Override
    public String resolve(HttpServletRequest req) {
      String v = firstToken(req.getHeader(header));
      return (v == null || v.isBlank()) ? (header + ":_") : v.trim();
    }
  }

  private static final class PathPart implements KeyPart {
    @Override
    public String resolve(HttpServletRequest req) {
      String p = req.getRequestURI();
      return (p == null || p.isBlank()) ? "/" : p;
    }
  }

  /** Per-key token bucket (nanosecond resolution). */
  private static final class TokenBucket {
    private long tokens;
    private long lastRefillNanos;

    /** Read during pruning without synchronization; updated inside synchronized code path. */
    private volatile long lastSeenNanos;

    TokenBucket(Policy p) {
      this.tokens = p.capacity;
      long now = System.nanoTime();
      this.lastRefillNanos = now;
      this.lastSeenNanos = now;
    }

    synchronized ConsumeResult tryConsumeOne(Policy p) {
      long now = System.nanoTime();
      lastSeenNanos = now;

      if (now > lastRefillNanos) {
        long elapsed = now - lastRefillNanos;
        long steps = elapsed / p.periodNanos;
        if (steps > 0) {
          long add = Math.multiplyExact(steps, p.refillTokens);
          tokens = Math.min(p.capacity, tokens + add);
          lastRefillNanos += steps * p.periodNanos;
        }
      }

      if (tokens > 0) {
        tokens--;
        // time to full bucket ~ (missing tokens / refill rate) * period
        long missing = p.capacity - tokens;
        long toFullNanos = (missing <= 0) ? 0 : (missing * p.periodNanos) / p.refillTokens;
        long resetSec = Math.max(0, toFullNanos / 1_000_000_000L);
        return new ConsumeResult(true, tokens, resetSec);
      }

      long nanosUntilNext = Math.max(0, p.periodNanos - (now - lastRefillNanos));
      long resetSec = nanosUntilNext / 1_000_000_000L;
      return new ConsumeResult(false, 0, resetSec);
    }
  }

  private record ConsumeResult(boolean allowed, long remaining, long resetSeconds) {}

  // ---------------- Utilities ----------------

  private static List<KeyPart> parseKeySpec(List<String> tokens) {
    List<KeyPart> parts = new ArrayList<>();
    if (tokens != null) {
      for (String t : tokens) {
        if (t == null || t.isBlank()) {
          continue;
        }
        String s = t.trim();
        if (KEY_IP.equals(s)) {
          parts.add(new IpPart());
        } else if (KEY_TENANT.equals(s)) {
          parts.add(new TenantPart());
        } else if (KEY_PATH.equals(s)) {
          parts.add(new PathPart());
        } else if (s.startsWith(KEY_HEADER)) {
          String header = s.substring(KEY_HEADER.length());
          if (!header.isBlank()) {
            parts.add(new HeaderPart(header));
          }
        }
      }
    }
    // Sane default if misconfigured
    if (parts.isEmpty()) {
      parts.add(new TenantPart());
      parts.add(new IpPart());
    }
    return parts;
  }

  private static Policy ensurePolicy(Policy p) {
    return (p != null) ? p : new Policy(100, 100, Duration.ofMinutes(1));
  }

  private static LinkedHashMap<String, Policy> toPolicyMap(Map<String, Policy> in) {
    LinkedHashMap<String, Policy> out = new LinkedHashMap<>();
    if (in != null) {
      in.forEach((k, v) -> out.put(k, ensurePolicy(v)));
    }
    return out;
  }

  private static String firstToken(String v) {
    if (v == null) {
      return null;
    }
    int comma = v.indexOf(',');
    return (comma >= 0 ? v.substring(0, comma) : v).trim();
  }

  private static String redact(String s) {
    if (s == null || s.length() <= 3) {
      return "***";
    }
    return s.charAt(0) + "***" + s.charAt(s.length() - 1);
  }
}
