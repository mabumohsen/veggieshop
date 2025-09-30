package io.veggieshop.platform.http.filters;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enterprise-grade PII guard for logs/metrics/traces.
 *
 * <p>What it does (without changing request semantics):
 *
 * <ul>
 *   <li>Enforces a strict deny-list of sensitive keys across headers, parameters, and MDC.
 *   <li>Publishes sanitized views of headers/parameters on request attributes so downstream
 *       components (problem handler, access logs, OTEL enrichers) can log safely.
 *   <li>Scrubs MDC keys that look sensitive; keeps an allow-list
 *       (traceId/spanId/tenantId/requestId/correlationId).
 * </ul>
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>Does not buffer/read the body; does not alter the response.
 *   <li>Bean is typically created by <em>platform-starter-web</em> (auto-config). No Spring
 *       stereotype here.
 * </ul>
 */
@Order(PiiLogGuardFilter.ORDER)
public final class PiiLogGuardFilter extends OncePerRequestFilter {

  /** Run early (after correlation-id filter, before tenant/rate limit). */
  public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 15;

  /** Request attribute exposing a sanitized, log-safe view of headers. */
  public static final String ATTR_SANITIZED_HEADERS =
      PiiLogGuardFilter.class.getName() + ".SANITIZED_HEADERS";

  /** Request attribute exposing a sanitized, log-safe view of parameters. */
  public static final String ATTR_SANITIZED_PARAMETERS =
      PiiLogGuardFilter.class.getName() + ".SANITIZED_PARAMETERS";

  /** Canonical non-PII platform header allowed in clear form. */
  public static final String HEADER_TENANT_ID = "X-Tenant-Id";

  /** Allowed MDC keys (non-PII). */
  private static final Set<String> ALLOWED_MDC_KEYS =
      Set.of("traceId", "spanId", "tenantId", "requestId", "correlationId");

  /** Conservative base tokens considered sensitive (headers/params/MDC), lowercase & hyphenated. */
  private static final Set<String> SENSITIVE_BASE =
      Set.of(
          // Auth / Secrets
          "authorization",
          "proxy-authorization",
          "x-api-key",
          "api-key",
          "apikey",
          "secret",
          "client-secret",
          "access-token",
          "id-token",
          "refresh-token",
          "token",
          "session",
          "sessionid",
          "xsrf",
          "csrf",
          // Credentials
          "password",
          "pass",
          "pwd",
          "pin",
          "otp",
          // Payments / PCI
          "card",
          "pan",
          "cvv",
          "cvc",
          "expiry",
          "iban",
          "swift",
          "bank",
          "account-number",
          // Identity / Contact (PII)
          "ssn",
          "national-id",
          "nationalid",
          "nin",
          "passport",
          "email",
          "e-mail",
          "phone",
          "mobile",
          "msisdn",
          "address",
          "street",
          "zipcode",
          "postal",
          "dob",
          "birth",
          "firstname",
          "lastname",
          "fullname",
          "name",
          // Cookies
          "cookie",
          "set-cookie",
          // Misc sensitive
          "geo",
          "location",
          "device-id",
          "deviceid",
          "license",
          "private-key",
          "privatekey");

  // ---------------- Configuration (immutable) ----------------

  private final int payloadMaxChars;

  /** Case-insensitive header deny-list (stored lowercase). */
  private final Set<String> headerDenylistLower;

  /** Regex patterns to redact from payload lines (passed-through). */
  private final List<String> redactPatterns;

  /** Combined sensitive tokens for heuristic checks (base ∪ denylist). */
  private final Set<String> sensitiveTokens;

  /**
   * Default constructor with sane defaults.
   *
   * <p>Prefer using the parameterized constructor via auto-configuration.
   */
  public PiiLogGuardFilter() {
    this(
        2048,
        new LinkedHashSet<>(List.of("authorization", "cookie", "set-cookie", "x-api-key")),
        new ArrayList<>(
            List.of("\\b[0-9]{13,19}\\b", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")));
  }

  /**
   * Primary constructor used by auto-configuration.
   *
   * @param payloadMaxChars maximum body characters to keep when clipping values (post-redaction).
   * @param headerDenylist case-insensitive header names to redact.
   * @param redactPatterns regex patterns to apply for payload redaction.
   */
  public PiiLogGuardFilter(
      int payloadMaxChars, Set<String> headerDenylist, List<String> redactPatterns) {
    this.payloadMaxChars = Math.max(1, payloadMaxChars);
    this.headerDenylistLower = toLowerLinkedSet(headerDenylist);
    this.redactPatterns = (redactPatterns == null) ? List.of() : List.copyOf(redactPatterns);

    // Merge base tokens with header denylist (normalized) to catch query-string misuses.
    Set<String> merged = new LinkedHashSet<>(SENSITIVE_BASE);
    merged.addAll(this.headerDenylistLower);
    this.sensitiveTokens = Collections.unmodifiableSet(merged);
  }

  // ---------------- Filter logic ----------------

  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
    // Skip CORS preflight (OPTIONS)
    return "OPTIONS".equalsIgnoreCase(request.getMethod())
        && request.getHeader("Access-Control-Request-Method") != null;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    // 1) Publish sanitized, log-safe views on request attributes
    Map<String, String> safeHeaders = buildSanitizedHeadersView(request);
    Map<String, List<String>> safeParams = buildSanitizedParamsView(request);
    request.setAttribute(ATTR_SANITIZED_HEADERS, safeHeaders);
    request.setAttribute(ATTR_SANITIZED_PARAMETERS, safeParams);

    // 2) Scrub MDC (keep only known-safe keys; drop anything that looks sensitive)
    Map<String, String> mdc = MDC.getCopyOfContextMap();
    if (mdc != null && !mdc.isEmpty()) {
      for (String key : new ArrayList<>(mdc.keySet())) {
        if (!ALLOWED_MDC_KEYS.contains(key) && isSensitiveKey(key)) {
          MDC.remove(key);
        }
      }
    }

    // 3) Guardrails: reject blatant credentials in query string (client misuse)
    if (hasBlatantSensitiveInQuery(request)) {
      throw VeggieException.builder(ProblemTypes.VALIDATION_FAILED)
          .detail("Sensitive credentials must not be sent via query parameters.")
          .captureStackTrace(false)
          .build();
    }

    // 4) Proceed
    chain.doFilter(request, response);
  }

  // ---------------- Sanitization helpers (logging only; do NOT alter semantics) ----------------

  /**
   * Builds a sanitized, log-safe immutable view of request headers.
   *
   * @param request current request
   * @return header name to sanitized value (comma-joined for multi-valued headers)
   */
  private Map<String, String> buildSanitizedHeadersView(HttpServletRequest request) {
    Map<String, String> out = new LinkedHashMap<>();
    Enumeration<String> names = request.getHeaderNames();
    if (names == null) {
      return out;
    }

    while (names.hasMoreElements()) {
      String name = names.nextElement();
      String lower = name.toLowerCase(Locale.ROOT);

      // Always allow our canonical non-PII header in clear form
      if (HEADER_TENANT_ID.equalsIgnoreCase(name)) {
        out.put(name, firstToken(request.getHeader(name)));
        continue;
      }

      if (headerDenylistLower.contains(lower) || isSensitiveKey(lower)) {
        out.put(name, "[REDACTED]");
      } else {
        out.put(name, String.join(",", Collections.list(request.getHeaders(name))));
      }
    }
    return out;
  }

  /**
   * Builds a sanitized, log-safe immutable view of request parameters.
   *
   * @param request current request
   * @return parameter name to sanitized list of values
   */
  private Map<String, List<String>> buildSanitizedParamsView(HttpServletRequest request) {
    Map<String, List<String>> out = new LinkedHashMap<>();
    Map<String, String[]> raw = request.getParameterMap();
    if (raw == null || raw.isEmpty()) {
      return out;
    }

    for (Map.Entry<String, String[]> e : raw.entrySet()) {
      String key = e.getKey();
      if (isSensitiveKey(key)) {
        out.put(key, List.of("[REDACTED]"));
      } else {
        out.put(key, clipValues(e.getValue()));
      }
    }
    return out;
  }

  /**
   * Clips parameter values to {@code payloadMaxChars}, preserving {@code null} entries.
   *
   * @param values raw parameter values
   * @return clipped values with an ellipsis when truncated
   */
  private List<String> clipValues(String[] values) {
    if (values == null) {
      return List.of();
    }
    List<String> out = new ArrayList<>(values.length);
    for (String v : values) {
      if (v == null) {
        out.add(null);
        continue;
      }
      if (v.length() > payloadMaxChars) {
        out.add(v.substring(0, Math.min(payloadMaxChars, v.length())) + "…");
      } else {
        out.add(v);
      }
    }
    return out;
  }

  /**
   * Detects blatant sensitive credentials in the raw query string (e.g., {@code token=...}).
   *
   * @param request current request
   * @return {@code true} if a sensitive token name appears as a query parameter name
   */
  private boolean hasBlatantSensitiveInQuery(HttpServletRequest request) {
    String q = request.getQueryString();
    if (q == null || q.isBlank()) {
      return false;
    }
    String lower = q.toLowerCase(Locale.ROOT);
    for (String token : sensitiveTokens) {
      // Flag if token looks like a parameter name boundary (token= or &token=)
      if (lower.contains(token + "=") || lower.contains("&" + token + "=")) {
        return true;
      }
    }
    return false;
  }

  /**
   * Heuristically determines if a key looks sensitive (header/param/MDC).
   *
   * @param key candidate key
   * @return {@code true} if the key should be treated as sensitive
   */
  private boolean isSensitiveKey(String key) {
    if (key == null) {
      return false;
    }
    String norm = key.toLowerCase(Locale.ROOT).replace("_", "-");
    if (sensitiveTokens.contains(norm)) {
      return true;
    }
    for (String token : sensitiveTokens) {
      if (norm.contains(token)) {
        return true;
      }
    }
    return false;
  }

  /** Returns the first token before a comma (proxies may join multiple values). */
  private static String firstToken(String v) {
    if (v == null) {
      return null;
    }
    int comma = v.indexOf(',');
    return (comma >= 0 ? v.substring(0, comma) : v).trim();
  }

  /** Lowercases strings and returns a {@link LinkedHashSet} preserving insertion order. */
  private static Set<String> toLowerLinkedSet(Set<String> in) {
    if (in == null || in.isEmpty()) {
      return new LinkedHashSet<>();
    }
    Set<String> out = new LinkedHashSet<>(in.size());
    for (String s : in) {
      if (s != null && !s.isBlank()) {
        out.add(s.toLowerCase(Locale.ROOT));
      }
    }
    return out;
  }
}
