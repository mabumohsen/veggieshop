package io.veggieshop.platform.http.filters;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Servlet {@code Filter} that enforces OIDC JWT Bearer authentication using Nimbus JOSE + JWT.
 *
 * <p>Key characteristics:
 *
 * <ul>
 *   <li>Skips CORS preflight and requests matching configured public paths.
 *   <li>Extracts {@code Authorization: Bearer &lt;JWT&gt;} and verifies signature and claims.
 *   <li>Validates issuer, accepted audience (optional), token temporal claims with skew, and JWS
 *       algorithm equality (header vs. expected).
 *   <li>Performs multi-tenant guard by matching {@code tenantId} claim with request/ctx tenant.
 *   <li>Publishes an immutable {@link OidcPrincipal} as a request attribute for downstream use.
 * </ul>
 *
 * <p>Instantiation is typically done by a starter via the {@code of(...)} factories; this class
 * carries no Spring stereotype.
 */
@Order(OidcJwtAuthFilter.ORDER)
public final class OidcJwtAuthFilter extends OncePerRequestFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OidcJwtAuthFilter.class);

  /** Runs after rate limiting to avoid expensive verification on rejected requests. */
  public static final int ORDER = RateLimitFilter.ORDER + 10;

  // -------------------- Headers/attrs --------------------
  public static final String HEADER_AUTHORIZATION = "Authorization";
  public static final String HEADER_TENANT_ID = TenantContext.REQUEST_HEADER;
  public static final String REQUEST_ATTR_PRINCIPAL =
      OidcJwtAuthFilter.class.getName() + ".PRINCIPAL";

  private static final AntPathMatcher ANT = new AntPathMatcher();
  private static final String REALM = "veggieshop";

  /** Default allow-list of public paths when none is provided. */
  private static final List<String> DEFAULT_PUBLIC_PATHS =
      List.of("/error", "/favicon.ico", "/actuator/**", "/_internal/**", "/internal/**");

  // -------------------- Config & verification --------------------
  private final List<String> publicPaths;
  private final Duration clockSkew;
  private final String expectedIssuer;
  private final Optional<String> expectedAudience;
  private final String expectedAlg; // e.g., RS256
  private final Clock clock = Clock.systemUTC();
  private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  // -------------------- Factories --------------------

  /**
   * Factory that builds a Nimbus JWT processor from issuer and JWKS endpoint.
   *
   * @param issuer expected {@code iss} claim value (required)
   * @param jwksUri JWKS URI; if {@code null/blank}, defaults to {@code
   *     {issuer}/.well-known/jwks.json}
   * @param allowedAlgs list of accepted JWS algorithms (first is enforced; defaults to RS256)
   * @param clockSkew acceptable clock skew for temporal claims
   * @param audience optional required audience
   * @param publicPaths request-path patterns to bypass authentication
   * @return configured {@link OidcJwtAuthFilter}
   */
  public static OidcJwtAuthFilter of(
      String issuer,
      String jwksUri,
      List<String> allowedAlgs,
      Duration clockSkew,
      String audience,
      List<String> publicPaths) {
    String alg = (allowedAlgs == null || allowedAlgs.isEmpty()) ? "RS256" : allowedAlgs.get(0);

    DefaultResourceRetriever retriever = new DefaultResourceRetriever(2000, 2000, 4096);

    final URL jwksUrl;
    try {
      jwksUrl =
          URI.create(
                  (jwksUri == null || jwksUri.isBlank())
                      ? defaultJwksFromIssuer(requireNonBlank(issuer, "issuer required"))
                      : jwksUri)
              .toURL();
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Invalid JWKS URI: " + jwksUri, e);
    }

    JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl, retriever).build();
    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.parse(alg), jwkSource);

    DefaultJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
    proc.setJWSKeySelector(keySelector);

    return new OidcJwtAuthFilter(
        issuer, alg, clockSkew, audience, normalizePublicPaths(publicPaths), proc);
  }

  /** Factory variant for supplying a custom {@link ConfigurableJWTProcessor}. */
  public static OidcJwtAuthFilter of(
      String issuer,
      List<String> allowedAlgs,
      Duration clockSkew,
      String audience,
      List<String> publicPaths,
      ConfigurableJWTProcessor<SecurityContext> proc) {
    String alg = (allowedAlgs == null || allowedAlgs.isEmpty()) ? "RS256" : allowedAlgs.get(0);
    return new OidcJwtAuthFilter(
        issuer,
        alg,
        clockSkew,
        audience,
        normalizePublicPaths(publicPaths),
        Objects.requireNonNull(proc, "jwtProcessor"));
  }

  // -------------------- Constructor --------------------
  OidcJwtAuthFilter(
      String issuer,
      String expectedAlg,
      Duration clockSkew,
      String audience,
      List<String> publicPaths,
      ConfigurableJWTProcessor<SecurityContext> custom) {
    this.expectedIssuer = requireNonBlank(issuer, "issuer required");
    this.clockSkew = Objects.requireNonNullElse(clockSkew, Duration.ofSeconds(60));
    this.expectedAudience = Optional.ofNullable(audience).filter(s -> !s.isBlank());
    this.expectedAlg = (expectedAlg == null || expectedAlg.isBlank()) ? "RS256" : expectedAlg;
    this.jwtProcessor = Objects.requireNonNull(custom, "jwtProcessor");
    this.publicPaths = normalizePublicPaths(publicPaths);
  }

  private static List<String> normalizePublicPaths(List<String> in) {
    if (in == null || in.isEmpty()) {
      return DEFAULT_PUBLIC_PATHS;
    }
    List<String> out = new ArrayList<>(in.size());
    for (String p : in) {
      if (p != null && !p.isBlank()) {
        out.add(p.trim());
      }
    }
    return out.isEmpty() ? DEFAULT_PUBLIC_PATHS : List.copyOf(out);
  }

  // -------------------- Filter logic --------------------

  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())
        && request.getHeader("Access-Control-Request-Method") != null) {
      return true;
    }
    String path = request.getRequestURI();
    if (path == null || path.isBlank()) {
      return false;
    }
    for (String pattern : publicPaths) {
      if (ANT.match(pattern, path)) {
        return true;
      }
    }
    return false;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain chain)
      throws ServletException, IOException {

    // 1) Authorization: Bearer
    final String auth = request.getHeader(HEADER_AUTHORIZATION);
    if (auth == null || auth.isBlank()) {
      setWwwAuthenticate(response, "invalid_request", "Missing Authorization header");
      throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
          .detail("Authorization header is required")
          .captureStackTrace(false)
          .build();
    }
    final String token = extractBearer(auth).orElse(null);
    if (token == null) {
      setWwwAuthenticate(response, "invalid_request", "Authorization type must be Bearer");
      throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
          .detail("Authorization must be Bearer")
          .captureStackTrace(false)
          .build();
    }

    // 2) Verify & decode
    final JWTClaimsSet claims;
    try {
      claims = jwtProcessor.process(token, null);
    } catch (BadJWTException e) {
      String msg = (e.getMessage() == null ? "Invalid token" : e.getMessage());
      setWwwAuthenticate(response, "invalid_token", msg);
      throw VeggieException.builder(ProblemTypes.JWT_INVALID)
          .detail(msg)
          .cause(e)
          .captureStackTrace(false)
          .build();
    } catch (Exception e) {
      setWwwAuthenticate(response, "invalid_token", "Unable to verify token");
      throw VeggieException.builder(ProblemTypes.JWT_INVALID)
          .detail("Unable to verify token")
          .cause(e)
          .captureStackTrace(false)
          .build();
    }

    // 2.1) Enforce alg exactly matches header
    try {
      String algInHeader = SignedJWT.parse(token).getHeader().getAlgorithm().getName();
      if (!expectedAlg.equals(algInHeader)) {
        setWwwAuthenticate(response, "invalid_token", "Unsupported JWS alg");
        throw VeggieException.builder(ProblemTypes.JWT_INVALID)
            .detail("Unsupported JWS algorithm")
            .captureStackTrace(false)
            .build();
      }
    } catch (ParseException ex) {
      // Token already verified above; header parse failing here is non-fatal but logged for
      // forensics.
      LOG.debug("Failed to parse JWT header algorithm; token already processed by processor.", ex);
    }

    // 3) Issuer / audience / temporal with skew
    if (!Objects.equals(expectedIssuer, claims.getIssuer())) {
      setWwwAuthenticate(response, "invalid_token", "Issuer mismatch");
      throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
          .detail("Invalid token issuer")
          .captureStackTrace(false)
          .build();
    }
    expectedAudience.ifPresent(
        aud -> {
          List<String> claimAud = claims.getAudience();
          if (claimAud == null || !claimAud.contains(aud)) {
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                .detail("Token audience not accepted")
                .captureStackTrace(false)
                .build();
          }
        });

    long now = clock.instant().getEpochSecond();
    Date exp = claims.getExpirationTime();
    Date nbf = claims.getNotBeforeTime();
    if (exp != null && (exp.toInstant().getEpochSecond() + clockSkew.getSeconds()) < now) {
      setWwwAuthenticate(response, "invalid_token", "Token expired");
      throw VeggieException.builder(ProblemTypes.JWT_INVALID)
          .detail("Token has expired")
          .captureStackTrace(false)
          .build();
    }
    if (nbf != null && (nbf.toInstant().getEpochSecond() - clockSkew.getSeconds()) > now) {
      setWwwAuthenticate(response, "invalid_token", "Token not yet valid");
      throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
          .detail("Token not yet valid")
          .captureStackTrace(false)
          .build();
    }

    // 4) Multi-tenant guard
    String claimTenant = stringClaim(claims, "tenantId");
    if (claimTenant == null || claimTenant.isBlank()) {
      setWwwAuthenticate(response, "insufficient_scope", "tenantId claim required");
      throw VeggieException.builder(ProblemTypes.AUTHORIZATION_DENIED)
          .detail("Missing tenantId claim")
          .captureStackTrace(false)
          .build();
    }
    String headerTenant = firstHeaderValue(request.getHeader(HEADER_TENANT_ID));
    TenantId ctxTenant = TenantContext.currentTenantId().orElse(null);
    String effectiveTenant = (ctxTenant != null ? ctxTenant.value() : headerTenant);
    if (effectiveTenant != null && !claimTenant.equals(effectiveTenant)) {
      setWwwAuthenticate(response, "insufficient_scope", "tenant mismatch");
      throw VeggieException.builder(ProblemTypes.TENANT_MISMATCH)
          .detail("Tenant mismatch between token and request")
          .captureStackTrace(false)
          .build();
    }

    // 5) Build principal (no PII logging)
    OidcPrincipal principal =
        new OidcPrincipal(
            claims.getSubject(),
            claimTenant,
            stringClaim(claims, "vendorId"),
            toStringSet(claims.getClaim("roles")),
            mergeScopes(claims.getClaim("scope"), claims.getClaim("scp")),
            toStringSet(claims.getClaim("amr")),
            longClaim(claims.getClaim("auth_time")));
    request.setAttribute(REQUEST_ATTR_PRINCIPAL, principal);

    try {
      chain.doFilter(request, response);
    } finally {
      request.removeAttribute(REQUEST_ATTR_PRINCIPAL);
    }
  }

  // -------------------- helpers --------------------

  /**
   * Extracts the Bearer token from an Authorization header.
   *
   * @return an {@link Optional} containing the token when present and well-formed
   */
  private static Optional<String> extractBearer(String authHeader) {
    String v = authHeader.trim();
    int space = v.indexOf(' ');
    if (space < 0) {
      return Optional.empty();
    }
    String scheme = v.substring(0, space);
    String token = v.substring(space + 1).trim();
    if (!"Bearer".equalsIgnoreCase(scheme) || token.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(token);
  }

  /** Returns the first header value before a comma (proxies may join multiple values). */
  private static String firstHeaderValue(String raw) {
    if (raw == null) {
      return null;
    }
    int comma = raw.indexOf(',');
    return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
  }

  /** Sets an RFC6750-compliant {@code WWW-Authenticate} header. */
  private static void setWwwAuthenticate(HttpServletResponse res, String error, String desc) {
    String v =
        "Bearer realm=\""
            + REALM
            + "\", error=\""
            + error
            + "\", error_description=\""
            + desc
            + "\"";
    res.setHeader("WWW-Authenticate", v);
  }

  /** Derives a JWKS URL from an issuer (appends {@code /.well-known/jwks.json}). */
  private static String defaultJwksFromIssuer(String issuer) {
    String base = issuer.endsWith("/") ? issuer : issuer + "/";
    return URI.create(base).resolve(".well-known/jwks.json").toString();
  }

  /** Ensures a string is non-blank, throwing {@link IllegalStateException} otherwise. */
  private static String requireNonBlank(String v, String msg) {
    if (v == null || v.isBlank()) {
      throw new IllegalStateException(msg);
    }
    return v;
  }

  private static String stringClaim(JWTClaimsSet claims, String name) {
    Object val = claims.getClaim(name);
    return (val == null) ? null : String.valueOf(val);
  }

  private static Long longClaim(Object v) {
    if (v instanceof Number n) {
      return n.longValue();
    }
    if (v instanceof String s) {
      try {
        return Long.parseLong(s);
      } catch (NumberFormatException ignore) {
        // intentionally ignore non-numeric auth_time values
      }
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static Set<String> toStringSet(Object v) {
    if (v == null) {
      return Set.of();
    }
    if (v instanceof String s) {
      return Arrays.stream(s.split("[\\s,]+"))
          .map(String::trim)
          .filter(x -> !x.isBlank())
          .collect(Collectors.toSet());
    }
    if (v instanceof Collection<?> c) {
      return c.stream().filter(Objects::nonNull).map(Object::toString).collect(Collectors.toSet());
    }
    return Set.of();
  }

  /** Merges scopes from either a space-delimited {@code scope} or an array {@code scp} claim. */
  private static Set<String> mergeScopes(Object scope, Object scp) {
    Set<String> out = new LinkedHashSet<>();
    out.addAll(toStringSet(scope));
    out.addAll(toStringSet(scp));
    return out;
  }

  /** Immutable principal exposed to downstream code. */
  public static final class OidcPrincipal {
    private final String subject;
    private final String tenantId;
    private final String vendorId;
    private final Set<String> roles;
    private final Set<String> scopes;
    private final Set<String> amr;
    private final Long authTimeEpochSeconds;

    /**
     * Creates an immutable principal view of the authenticated user.
     *
     * @param subject subject ("sub") claim
     * @param tenantId tenant identifier bound to the token
     * @param vendorId optional vendor/partner identifier
     * @param roles role names granted to the subject
     * @param scopes OAuth/OpenID scopes granted to the subject
     * @param amr Authentication Methods References ("amr") claim values
     * @param authTimeEpochSeconds authentication time in epoch seconds; may be {@code null}
     */
    public OidcPrincipal(
        String subject,
        String tenantId,
        String vendorId,
        Set<String> roles,
        Set<String> scopes,
        Set<String> amr,
        Long authTimeEpochSeconds) {
      this.subject = subject;
      this.tenantId = tenantId;
      this.vendorId = vendorId;
      this.roles = (roles == null ? Set.of() : Set.copyOf(roles));
      this.scopes = (scopes == null ? Set.of() : Set.copyOf(scopes));
      this.amr = (amr == null ? Set.of() : Set.copyOf(amr));
      this.authTimeEpochSeconds = authTimeEpochSeconds;
    }

    /** Subject (sub) claim. */
    public String subject() {
      return subject;
    }

    /** Tenant identifier this token is bound to. */
    public String tenantId() {
      return tenantId;
    }

    /** Optional vendor identifier (e.g., partner id). */
    public Optional<String> vendorId() {
      return Optional.ofNullable(vendorId);
    }

    /** Role names granted to the subject. */
    public Set<String> roles() {
      return roles;
    }

    /** OAuth/OpenID scopes granted to the subject. */
    public Set<String> scopes() {
      return scopes;
    }

    /** Authentication Methods References (amr) claim. */
    public Set<String> amr() {
      return amr;
    }

    /** Authentication time in epoch seconds, when present. */
    public Optional<Long> authTimeEpochSeconds() {
      return Optional.ofNullable(authTimeEpochSeconds);
    }
  }
}
