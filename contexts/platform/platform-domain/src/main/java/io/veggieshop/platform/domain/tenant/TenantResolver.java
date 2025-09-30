package io.veggieshop.platform.domain.tenant;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Enterprise-grade, framework-agnostic resolver of {@link TenantId} from multiple carriers.
 *
 * <p>Precedence (strongest → weakest): EXPLICIT &gt; HTTP_HEADER &gt; JWT_CLAIM &gt; MESSAGE_HEADER
 * &gt; (optionally) MDC.
 *
 * <p>By default:
 *
 * <ul>
 *   <li>Consistency is enforced across carriers (fail on mismatch).
 *   <li>MDC fallback is <b>disabled</b> (safer; observability only).
 * </ul>
 */
public final class TenantResolver {

  private static final Logger LOG = LoggerFactory.getLogger(TenantResolver.class);

  // -------- Default config values --------

  private static final List<String> DEFAULT_HEADER_ALIASES =
      List.of(
          TenantContext.REQUEST_HEADER, // "X-Tenant-Id"
          "x-tenant-id",
          "X_TENANT_ID",
          "Tenant-Id",
          "tenant-id");

  private static final List<String> DEFAULT_CLAIM_CANDIDATES =
      List.of(
          "https://veggieshop.io/tenant_id",
          "https://schemas.veggieshop.io/tenant_id",
          "tenantId",
          "tenant_id",
          "tid");

  private static final List<String> DEFAULT_MSG_HEADER_ALIASES =
      List.of("x-tenant-id", "tenant-id", "tenantId", "x_tenant_id");

  // -------- Configuration --------

  /**
   * Immutable configuration for {@link TenantResolver}.
   *
   * <p>Lists are defensively copied and exposed as unmodifiable views to satisfy SpotBugs'
   * EI_EXPOSE_REP checks.
   */
  public record Config(
      List<String> headerAliases,
      List<String> claimCandidates,
      List<String> messageHeaderAliases,
      boolean enforceConsistency,
      boolean allowMdcFallback) {

    /** Canonical constructor that defensively copies list components. */
    public Config(
        List<String> headerAliases,
        List<String> claimCandidates,
        List<String> messageHeaderAliases,
        boolean enforceConsistency,
        boolean allowMdcFallback) {
      this.headerAliases = List.copyOf(Objects.requireNonNull(headerAliases, "headerAliases"));
      this.claimCandidates =
          List.copyOf(Objects.requireNonNull(claimCandidates, "claimCandidates"));
      this.messageHeaderAliases =
          List.copyOf(Objects.requireNonNull(messageHeaderAliases, "messageHeaderAliases"));
      this.enforceConsistency = enforceConsistency;
      this.allowMdcFallback = allowMdcFallback;
    }

    /** Returns a defensive, unmodifiable view of header aliases. */
    @Override
    public List<String> headerAliases() {
      return List.copyOf(headerAliases);
    }

    /** Returns a defensive, unmodifiable view of claim candidates. */
    @Override
    public List<String> claimCandidates() {
      return List.copyOf(claimCandidates);
    }

    /** Returns a defensive, unmodifiable view of message header aliases. */
    @Override
    public List<String> messageHeaderAliases() {
      return List.copyOf(messageHeaderAliases);
    }

    /** Default configuration. */
    public static Config defaults() {
      return new Config(
          DEFAULT_HEADER_ALIASES,
          DEFAULT_CLAIM_CANDIDATES,
          DEFAULT_MSG_HEADER_ALIASES,
          /* enforceConsistency */ true,
          /* allowMdcFallback  */ false);
    }
  }

  private final Config cfg;

  /** Creates a resolver with {@link Config#defaults()}. */
  public TenantResolver() {
    this(Config.defaults());
  }

  /** Creates a resolver with the provided configuration. */
  public TenantResolver(Config cfg) {
    this.cfg = Objects.requireNonNull(cfg, "cfg");
  }

  // -------- Public API --------

  /**
   * Resolve a tenant from the given carriers using configured precedence and rules.
   *
   * @param explicit explicit {@link TenantId} if already known
   * @param httpHeaders HTTP headers (case-insensitive keys)
   * @param jwtClaims decoded JWT claims
   * @param messageHeadersBytes message headers map (bytes payload)
   * @return the chosen resolution (id + source)
   * @throws NoSuchElementException if no carrier provided a tenant id
   * @throws IllegalStateException if {@code enforceConsistency} and carriers disagree
   */
  public Resolution resolve(
      TenantId explicit,
      Map<String, ?> httpHeaders,
      Map<String, ?> jwtClaims,
      Map<String, byte[]> messageHeadersBytes) {

    final List<Resolution> candidates = new ArrayList<>(4);

    if (explicit != null) {
      candidates.add(new Resolution(explicit, Source.EXPLICIT));
    }
    resolveFromHttpHeaders(httpHeaders).ifPresent(candidates::add);
    resolveFromJwtClaims(jwtClaims).ifPresent(candidates::add);
    resolveFromMessageHeaders(messageHeadersBytes).ifPresent(candidates::add);

    if (cfg.allowMdcFallback) {
      resolveFromMdc().ifPresent(candidates::add);
    }

    if (candidates.isEmpty()) {
      throw new NoSuchElementException(
          "Unable to resolve tenant: none of [explicit, HTTP header, JWT claim, "
              + "message header"
              + (cfg.allowMdcFallback ? ", MDC" : "")
              + "] provided a value");
    }

    if (cfg.enforceConsistency) {
      assertConsistent(candidates);
    }

    final Resolution chosen = candidates.get(0); // by precedence
    if (LOG.isDebugEnabled()) {
      LOG.debug("Tenant resolved: id='{}' source={}", chosen.tenantId().value(), chosen.source());
    }
    return chosen;
  }

  /**
   * Convenience one-shot resolver using {@link Config#defaults()}.
   *
   * @see #resolve(TenantId, Map, Map, Map)
   */
  public static Resolution resolveDefault(
      TenantId explicit,
      Map<String, ?> httpHeaders,
      Map<String, ?> jwtClaims,
      Map<String, byte[]> messageHeadersBytes) {
    return new TenantResolver().resolve(explicit, httpHeaders, jwtClaims, messageHeadersBytes);
  }

  // -------- Individual carriers --------

  /** Resolve from HTTP headers (case-insensitive). */
  public Optional<Resolution> resolveFromHttpHeaders(Map<String, ?> headers) {
    if (headers == null || headers.isEmpty()) {
      return Optional.empty();
    }
    return findFirstString(headers, cfg.headerAliases())
        .flatMap(this::toTenantId)
        .map(id -> new Resolution(id, Source.HTTP_HEADER));
  }

  /** Resolve from JWT claims. */
  public Optional<Resolution> resolveFromJwtClaims(Map<String, ?> claims) {
    if (claims == null || claims.isEmpty()) {
      return Optional.empty();
    }
    return findFirstString(claims, cfg.claimCandidates())
        .flatMap(this::toTenantId)
        .map(id -> new Resolution(id, Source.JWT_CLAIM));
  }

  /** Resolve from message headers (byte[] values). */
  public Optional<Resolution> resolveFromMessageHeaders(Map<String, byte[]> headers) {
    if (headers == null || headers.isEmpty()) {
      return Optional.empty();
    }
    return findFirstBytes(headers, cfg.messageHeaderAliases())
        .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
        .flatMap(this::toTenantId)
        .map(id -> new Resolution(id, Source.MESSAGE_HEADER));
  }

  /** Resolve from logging MDC (only if {@code allowMdcFallback} is true). */
  public Optional<Resolution> resolveFromMdc() {
    final String mdc = MDC.get(TenantContext.MDC_TENANT_ID);
    return toTenantId(mdc).map(id -> new Resolution(id, Source.MDC));
  }

  // -------- Helpers --------

  /** Parse and validate a raw tenant id string into {@link TenantId}. */
  private Optional<TenantId> toTenantId(String raw) {
    if (raw == null) {
      return Optional.empty();
    }
    String t = raw.trim();
    if (t.isEmpty() || "null".equalsIgnoreCase(t)) {
      return Optional.empty();
    }
    try {
      return Optional.of(TenantId.of(t));
    } catch (IllegalArgumentException ex) {
      LOG.warn(
          "Rejected tenant identifier from carrier due to validation error: {}", ex.getMessage());
      return Optional.empty();
    }
  }

  /** Find first non-blank string value by checking aliases case-insensitively. */
  private static Optional<String> findFirstString(Map<String, ?> map, List<String> keys) {
    if (map == null || map.isEmpty()) {
      return Optional.empty();
    }
    Map<String, Object> ci = new HashMap<>(map.size());
    for (Map.Entry<String, ?> e : map.entrySet()) {
      if (e.getKey() != null) {
        ci.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
      }
    }
    for (String key : keys) {
      Object v = ci.get(key.toLowerCase(Locale.ROOT));
      if (v != null) {
        String s = String.valueOf(v).trim();
        if (!s.isEmpty()) {
          return Optional.of(s);
        }
      }
    }
    return Optional.empty();
  }

  /** Find first non-empty byte[] value by checking aliases case-insensitively. */
  private static Optional<byte[]> findFirstBytes(Map<String, byte[]> map, List<String> keys) {
    if (map == null || map.isEmpty()) {
      return Optional.empty();
    }
    Map<String, byte[]> ci = new HashMap<>(map.size());
    for (Map.Entry<String, byte[]> e : map.entrySet()) {
      if (e.getKey() != null) {
        ci.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
      }
    }
    for (String key : keys) {
      byte[] v = ci.get(key.toLowerCase(Locale.ROOT));
      if (v != null && v.length > 0) {
        return Optional.of(v);
      }
    }
    return Optional.empty();
  }

  /** Ensure all resolved candidates agree on the same tenant id. */
  private static void assertConsistent(List<Resolution> candidates) {
    if (candidates.size() <= 1) {
      return;
    }
    TenantId first = candidates.get(0).tenantId();
    for (int i = 1; i < candidates.size(); i++) {
      TenantId other = candidates.get(i).tenantId();
      if (!first.equals(other)) {
        Resolution c0 = candidates.get(0);
        Resolution ci = candidates.get(i);
        LOG.warn(
            "Inconsistent tenant identifiers across sources: chosen={}({}) conflicting={}({})",
            c0.tenantId().value(),
            c0.source(),
            ci.tenantId().value(),
            ci.source());
        throw new IllegalStateException(
            "Conflicting tenant identifiers provided by multiple sources");
      }
    }
  }

  // -------- Types --------

  /** Source carrier for the resolved tenant id. */
  public enum Source {
    EXPLICIT,
    HTTP_HEADER,
    JWT_CLAIM,
    MESSAGE_HEADER,
    MDC
  }

  /** Resolution result: the tenant id and the source it came from. */
  public record Resolution(TenantId tenantId, Source source) {
    public Resolution {
      Objects.requireNonNull(tenantId, "tenantId");
      Objects.requireNonNull(source, "source");
    }
  }
}
