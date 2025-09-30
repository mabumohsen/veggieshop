package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.application.consistency.ConsistencyService;
import io.veggieshop.platform.application.consistency.ReadYourWritesGuard;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enterprise-grade interceptor that establishes request-scoped consistency semantics.
 *
 * <p><strong>Responsibilities</strong>:
 *
 * <ul>
 *   <li>Opens a {@linkplain ConsistencyService request scope} based on the headers {@code
 *       If-Consistent-With} and {@code X-Consistency-Token}.
 *   <li>Propagates {@code If-Match} (ETag precondition) as a request attribute for downstream
 *       layers.
 *   <li>Enables Read-Your-Writes (RYW) before GET/HEAD handlers when the client supplied {@code
 *       If-Consistent-With} by waiting up to the configured maximum.
 * </ul>
 *
 * <p><strong>Ordering</strong>: Registered slightly ahead of controllers so attributes are visible
 * to handlers and advices. The starter module is expected to register and order this interceptor.
 *
 * @implSpec Scope is opened in {@link #preHandle(HttpServletRequest, HttpServletResponse, Object)}
 *     and closed in {@link #afterCompletion(HttpServletRequest, HttpServletResponse, Object,
 *     Exception)}.
 * @since 1.0.0
 */
@Order(ConsistencyPreconditionInterceptor.ORDER)
public final class ConsistencyPreconditionInterceptor implements HandlerInterceptor {

  /** Runs a bit before controllers so attributes are available to handlers/advices. */
  public static final int ORDER = Ordered.LOWEST_PRECEDENCE - 200;

  // ----- Canonical headers -----
  /** Client precondition carrying a required watermark/time bound. */
  public static final String HDR_IF_CONSISTENT_WITH = "If-Consistent-With";

  /** Previous token emitted by the server to drive causality across requests. */
  public static final String HDR_CONSISTENCY_TOKEN = "X-Consistency-Token";

  /** ETag-based write precondition. */
  public static final String HDR_IF_MATCH = "If-Match";

  /** Canonical tenant header used across the platform. */
  public static final String HDR_TENANT_ID = TenantContext.REQUEST_HEADER;

  // ----- Request attributes for downstream layers -----
  /** Holds the open {@link ConsistencyService.Scope}. */
  public static final String ATTR_SCOPE =
      ConsistencyPreconditionInterceptor.class.getName() + ".SCOPE";

  /** Echo of {@code If-Consistent-With} for downstream reads. */
  public static final String ATTR_IF_CONSISTENT_WITH =
      ConsistencyPreconditionInterceptor.class.getName() + ".IF_CONSISTENT_WITH";

  /** Raw {@code If-Match} value for write handlers. */
  public static final String ATTR_IF_MATCH_RAW =
      ConsistencyPreconditionInterceptor.class.getName() + ".IF_MATCH_RAW";

  /** Epoch millis deadline for best-effort RYW waiting. */
  public static final String ATTR_RYW_DEADLINE_EPOCH_MS =
      ConsistencyPreconditionInterceptor.class.getName() + ".RYW_DEADLINE_MS";

  // ----- Bypass allowlist (health/internal) -----
  private static final Set<String> ALLOWLIST_PREFIXES =
      Set.of("/actuator", "/internal", "/_internal");
  private static final Set<String> ALLOWLIST_EXACT = Set.of("/error", "/favicon.ico");

  private final ConsistencyService consistency;
  private final ReadYourWritesGuard rywGuard;

  /**
   * Creates a new interceptor.
   *
   * @param consistency consistency service used to open/close request scopes
   * @param rywGuard helper to await RYW when requested by the client
   */
  public ConsistencyPreconditionInterceptor(
      final ConsistencyService consistency, final ReadYourWritesGuard rywGuard) {
    this.consistency = Objects.requireNonNull(consistency, "consistency");
    this.rywGuard = Objects.requireNonNull(rywGuard, "rywGuard");
  }

  /**
   * Opens a consistency scope, optionally awaits RYW for safe reads, and forwards write
   * preconditions.
   *
   * <p>Behavior:
   *
   * <ol>
   *   <li>Bypasses CORS preflight and internal/health paths.
   *   <li>Resolves {@link TenantId} (expects {@link TenantContext} to be already populated; falls
   *       back to {@code X-Tenant-Id} header as a guard).
   *   <li>Opens a {@link ConsistencyService.Scope} using request headers.
   *   <li>For GET/HEAD with {@code If-Consistent-With}, records a deadline and asks {@link
   *       ReadYourWritesGuard} to await best-effort visibility.
   *   <li>For mutating methods, forwards {@code If-Match} to request attributes.
   * </ol>
   *
   * @return {@code true} to continue the chain
   */
  @Override
  public boolean preHandle(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final Object handler) {

    // CORS preflight and allowlisted paths
    if (shouldBypass(request)) {
      return true;
    }

    // Tenant resolution: prefer Context; guard with header if missing
    final TenantId tenant =
        TenantContext.currentTenantId()
            .orElseGet(
                () -> {
                  final String fromHeader = firstHeaderValue(request.getHeader(HDR_TENANT_ID));
                  if (fromHeader == null || fromHeader.isBlank()) {
                    throw new IllegalStateException("Missing required header: " + HDR_TENANT_ID);
                  }
                  return TenantId.of(fromHeader.trim());
                });

    final String method = request.getMethod();
    final boolean isRead = isSafeRead(method);
    final boolean isWrite = isMutating(method);

    // Open request scope (closed in afterCompletion)
    final String ifConsistentWith = trimToNull(request.getHeader(HDR_IF_CONSISTENT_WITH));
    final String priorToken = trimToNull(request.getHeader(HDR_CONSISTENCY_TOKEN));

    final ConsistencyService.Scope scope =
        consistency.openRequest(tenant.value(), ifConsistentWith, priorToken);
    request.setAttribute(ATTR_SCOPE, scope);

    // RYW for safe reads when client requested consistency
    if (isRead && ifConsistentWith != null) {
      request.setAttribute(ATTR_IF_CONSISTENT_WITH, ifConsistentWith);
      final long deadlineMs =
          System.currentTimeMillis() + consistency.properties().rywMaxWait().toMillis();
      request.setAttribute(ATTR_RYW_DEADLINE_EPOCH_MS, deadlineMs);

      // Best-effort wait
      rywGuard.awaitIfRequested();
    }

    // Forward If-Match for writes
    if (isWrite) {
      final String ifMatch = trimToNull(request.getHeader(HDR_IF_MATCH));
      if (ifMatch != null) {
        request.setAttribute(ATTR_IF_MATCH_RAW, ifMatch);
      }
    }

    return true;
  }

  /** Closes the consistency scope if one was opened during {@link #preHandle}. */
  @Override
  public void afterCompletion(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final Object handler,
      final Exception ex) {
    final Object s = request.getAttribute(ATTR_SCOPE);
    if (s instanceof ConsistencyService.Scope scope) {
      try {
        scope.close();
      } finally {
        request.removeAttribute(ATTR_SCOPE);
      }
    }
  }

  // --------------------------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------------------------

  private static boolean isSafeRead(final String method) {
    return switch (method) {
      case "GET", "HEAD" -> true;
      default -> false;
    };
  }

  private static boolean isMutating(final String method) {
    return switch (method) {
      case "POST", "PUT", "PATCH", "DELETE" -> true;
      default -> false;
    };
  }

  /**
   * Returns {@code true} if the request should bypass consistency handling: CORS preflight, exact
   * allowlist, or known internal prefixes.
   */
  private static boolean shouldBypass(final HttpServletRequest request) {
    // CORS preflight
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())
        && request.getHeader("Access-Control-Request-Method") != null) {
      return true;
    }

    final String path = request.getRequestURI();
    if (path == null || path.isEmpty()) {
      return false;
    }

    if (ALLOWLIST_EXACT.contains(path)) {
      return true;
    }

    for (final String p : ALLOWLIST_PREFIXES) {
      if (path.startsWith(p)) {
        return true;
      }
    }

    return false;
  }

  /** Returns the first value before a comma in a potentially comma-delimited header. */
  private static String firstHeaderValue(final String raw) {
    if (raw == null) {
      return null;
    }
    final int comma = raw.indexOf(',');
    return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
  }

  /** Trims the string and converts blank to {@code null}. */
  private static String trimToNull(final String s) {
    if (s == null) {
      return null;
    }
    final String t = s.trim();
    return t.isEmpty() ? null : t;
  }
}
