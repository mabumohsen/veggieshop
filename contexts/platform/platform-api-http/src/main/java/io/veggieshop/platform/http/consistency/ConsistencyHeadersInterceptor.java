package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.application.consistency.ConsistencyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

/**
 * Enterprise-grade interceptor that enriches HTTP responses with consistency metadata.
 *
 * <p><strong>Responsibilities</strong>:
 *
 * <ul>
 *   <li>Adds a {@code Vary: If-Consistent-With} header to responses so that upstream and
 *       intermediate caches key variants on the request precondition header.
 *   <li>Emits an {@code X-Consistency-Token} header on successful responses (2xx/3xx) when a
 *       tenant-scoped consistency context is available.
 *   <li>If an entity version was captured by {@link EtagResponseAdvice}, embeds that version into
 *       the emitted token to improve read-your-writes and causality guarantees.
 * </ul>
 *
 * <p><strong>Design notes</strong>:
 *
 * <ul>
 *   <li><em>Idempotent</em>: header mutation is additive and will not overwrite an existing {@code
 *       X-Consistency-Token} set by a controller.
 *   <li><em>Fail-safe</em>: tokens are never emitted for error responses (status &ge; 400).
 *   <li><em>Cache-aware</em>: {@code Vary} is appended exactly once while preserving any existing
 *       values.
 * </ul>
 *
 * @implSpec This interceptor performs all work in {@link #postHandle(HttpServletRequest,
 *     HttpServletResponse, Object, ModelAndView)} after controller invocation. It assumes that
 *     tenant resolution and consistency scope establishment were handled earlier in the chain (for
 *     example by a precondition interceptor).
 * @apiNote This component is framework-agnostic in behavior and only relies on Spring MVC’s
 *     interceptor SPI for integration.
 * @since 1.0.0
 * @see ConsistencyPreconditionInterceptor
 * @see EtagResponseAdvice
 */
@Order(ConsistencyHeadersInterceptor.ORDER)
public final class ConsistencyHeadersInterceptor implements HandlerInterceptor {

  /**
   * Interceptor order. Placed late in the chain so headers reflect the final response status and
   * body, but before common trailing concerns.
   */
  public static final int ORDER = Ordered.LOWEST_PRECEDENCE - 150;

  /** Name of the standard HTTP {@code Vary} header. */
  public static final String HDR_VARY = "Vary";

  /**
   * Name of the request precondition header that influences cache variants and token computation.
   * Delegated from {@link ConsistencyPreconditionInterceptor}.
   */
  public static final String HDR_IF_CONSISTENT_WITH =
      ConsistencyPreconditionInterceptor.HDR_IF_CONSISTENT_WITH;

  /**
   * Name of the response header that carries the emitted consistency token. Delegated from {@link
   * ConsistencyPreconditionInterceptor}.
   */
  public static final String HDR_CONSISTENCY_TOKEN =
      ConsistencyPreconditionInterceptor.HDR_CONSISTENCY_TOKEN;

  /**
   * Request attribute populated by {@link EtagResponseAdvice} when an entity version is available.
   * The value type is {@link Long}.
   */
  public static final String ATTR_ENTITY_VERSION = EtagResponseAdvice.ATTR_ENTITY_VERSION;

  private final ConsistencyService consistency;

  /**
   * Creates a new interceptor.
   *
   * @param consistency the consistency service used to emit tokens for the current tenant context
   * @throws NullPointerException if {@code consistency} is {@code null}
   */
  public ConsistencyHeadersInterceptor(final ConsistencyService consistency) {
    this.consistency = Objects.requireNonNull(consistency, "consistency");
  }

  /**
   * Adds consistency-related headers after controller execution.
   *
   * <p>Behavior:
   *
   * <ol>
   *   <li>Ensures the {@code Vary} header contains {@code If-Consistent-With}.
   *   <li>If the response is successful (&lt; 400), and no {@code X-Consistency-Token} is already
   *       set, and a tenant is present in the consistency scope, computes and adds a token.
   *   <li>If a {@link #ATTR_ENTITY_VERSION} attribute is present and is a {@link Long}, the value
   *       is forwarded to token emission.
   * </ol>
   *
   * @param request current HTTP request
   * @param response current HTTP response
   * @param handler chosen handler (unused)
   * @param modelAndView the {@link ModelAndView} (unused)
   */
  @Override
  public void postHandle(
      @NonNull final HttpServletRequest request,
      @NonNull final HttpServletResponse response,
      @NonNull final Object handler,
      final ModelAndView modelAndView) {

    // 1) Ensure "Vary: If-Consistent-With" is present exactly once.
    addVary(response, HDR_IF_CONSISTENT_WITH);

    // 2) Do not emit a token for error responses.
    final int status = response.getStatus();
    if (status >= 400) {
      return;
    }

    // 3) Respect tokens explicitly set by controllers.
    if (response.getHeader(HDR_CONSISTENCY_TOKEN) != null) {
      return;
    }

    // 4) Token emission requires an active tenant context.
    if (consistency.currentTenant().isEmpty()) {
      return;
    }

    // 5) Optional entity version sourced from response advice.
    Long version = null;
    final Object attr = request.getAttribute(ATTR_ENTITY_VERSION);
    if (attr instanceof Long v) {
      version = v;
    }

    final String token = consistency.emitTokenForCurrentTenant(version);
    response.addHeader(HDR_CONSISTENCY_TOKEN, token);
  }

  /**
   * Ensures the {@code Vary} header includes the given token, preserving existing values and
   * avoiding duplicates.
   *
   * @param response the response to mutate
   * @param headerName the vary token to include (case-insensitive)
   */
  private static void addVary(final HttpServletResponse response, final String headerName) {
    final String existing = response.getHeader(HDR_VARY);
    if (existing == null) {
      response.setHeader(HDR_VARY, headerName);
    } else if (!containsToken(existing, headerName)) {
      response.setHeader(HDR_VARY, existing + ", " + headerName);
    }
  }

  /**
   * Checks whether a comma-delimited {@code Vary} value already contains a token (case-insensitive,
   * trimmed).
   *
   * @param varyValue the raw {@code Vary} header value
   * @param token the token to search for
   * @return {@code true} if present; {@code false} otherwise
   */
  private static boolean containsToken(final String varyValue, final String token) {
    for (final String part : varyValue.split(",")) {
      if (part.trim().equalsIgnoreCase(token)) {
        return true;
      }
    }
    return false;
  }
}
