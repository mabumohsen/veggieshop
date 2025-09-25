package io.veggieshop.platform.http.filters;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

// Nimbus JOSE + JWT
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.BadJWTException;

@Order(OidcJwtAuthFilter.ORDER)
public final class OidcJwtAuthFilter extends OncePerRequestFilter {

    /**
     * Run after rate limiting (to avoid expensive JWT checks on throttled requests).
     */
    public static final int ORDER = RateLimitFilter.ORDER + 10;

    // -------------------- Headers/attrs --------------------
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_TENANT_ID = TenantFilter.HEADER_TENANT_ID;
    public static final String REQUEST_ATTR_PRINCIPAL = OidcJwtAuthFilter.class.getName() + ".PRINCIPAL";

    private static final AntPathMatcher ANT = new AntPathMatcher();

    /** Default public paths if none provided. */
    private static final List<String> DEFAULT_PUBLIC_PATHS = List.of(
            "/error", "/favicon.ico", "/actuator/**", "/_internal/**", "/internal/**"
    );

    // -------------------- Config & verification --------------------
    private final List<String> publicPaths;
    private final Duration clockSkew;
    private final String expectedIssuer;
    private final Optional<String> expectedAudience;
    private final String expectedAlg; // single alg (e.g., RS256)
    private final Clock clock = Clock.systemUTC();
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    // -------------------- Factories --------------------

    /**
     * Static factory used by starter-web (with explicit public paths).
     */
    public static OidcJwtAuthFilter of(
            String issuer,
            String jwksUri,                 // may be null/blank => derive from issuer
            List<String> allowedAlgs,       // pick first; default RS256
            Duration clockSkew,
            String audience,                // may be null
            List<String> publicPaths,       // may be null => defaults
            ConfigurableJWTProcessor<SecurityContext> proc
    ) {
        String alg = (allowedAlgs == null || allowedAlgs.isEmpty()) ? "RS256" : allowedAlgs.get(0);
        String effectiveJwks = (jwksUri == null || jwksUri.isBlank())
                ? defaultJwksFromIssuer(issuer)
                : jwksUri;
        return new OidcJwtAuthFilter(issuer, effectiveJwks, alg, clockSkew, audience, normalizePublicPaths(publicPaths), proc);
    }

    /**
     * Backward-compatible factory (uses default public paths).
     */
    public static OidcJwtAuthFilter of(
            String issuer,
            String jwksUri,
            List<String> allowedAlgs,
            Duration clockSkew,
            String audience,
            ConfigurableJWTProcessor<SecurityContext> proc
    ) {
        return of(issuer, jwksUri, allowedAlgs, clockSkew, audience, DEFAULT_PUBLIC_PATHS, proc);
    }

    // -------------------- Constructors --------------------

    /**
     * Environment/sys-props driven constructor (used rarely).
     */
    public OidcJwtAuthFilter() {
        this.expectedIssuer = requireNonBlank(
                get("veggieshop.security.oidc.issuer"),
                "veggieshop.security.oidc.issuer (OIDC issuer) must be configured"
        );
        String jwksUri = get("veggieshop.security.oidc.jwksUri");
        if (jwksUri == null || jwksUri.isBlank()) {
            jwksUri = defaultJwksFromIssuer(expectedIssuer);
        }

        // Allowed algs (pick first, validate exactly later)
        String allowedAlgsCsv = getOrDefault("veggieshop.security.oidc.allowedAlgs", "RS256,ES256,EdDSA");
        List<String> allowed = Arrays.stream(allowedAlgsCsv.split(","))
                .map(String::trim).filter(s -> !s.isBlank()).toList();
        this.expectedAlg = allowed.isEmpty() ? "RS256" : allowed.get(0);

        int skewSeconds = Integer.getInteger("veggieshop.security.oidc.clockSkewSeconds", 60);
        this.clockSkew = Duration.ofSeconds(skewSeconds);
        this.expectedAudience = Optional.ofNullable(get("veggieshop.security.oidc.audience")).filter(s -> !s.isBlank());

        try {
            DefaultResourceRetriever retriever = new DefaultResourceRetriever(2000, 2000, 4096);
            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwksUri), retriever);
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(JWSAlgorithm.parse(this.expectedAlg), jwkSource);
            DefaultJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
            proc.setJWSKeySelector(keySelector);
            this.jwtProcessor = proc;
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid JWKS URI: " + jwksUri, e);
        }

        // Initialize public paths with defaults
        this.publicPaths = DEFAULT_PUBLIC_PATHS;
    }

    // Package-private primary constructor (use the static factory).
    OidcJwtAuthFilter(String issuer,
                      String jwksUri,
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
        if (in == null || in.isEmpty()) return DEFAULT_PUBLIC_PATHS;
        List<String> out = new ArrayList<>(in.size());
        for (String p : in) {
            if (p != null && !p.isBlank()) out.add(p.trim());
        }
        return out.isEmpty() ? DEFAULT_PUBLIC_PATHS : List.copyOf(out);
    }

    // -------------------- Filter logic --------------------

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        // CORS preflight bypass
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null) {
            return true;
        }
        String path = request.getRequestURI();
        if (path == null || path.isBlank()) return false;
        for (String pattern : publicPaths) {
            if (ANT.match(pattern, path)) return true;
        }
        return false;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws ServletException, IOException {

        // 1) Extract bearer
        final String auth = request.getHeader(HEADER_AUTHORIZATION);
        if (auth == null || auth.isBlank()) {
            setWwwAuthenticate(response, "invalid_request", "Missing Authorization header");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Authorization header is required").captureStackTrace(false).build();
        }
        final String token = extractBearer(auth).orElse(null);
        if (token == null) {
            setWwwAuthenticate(response, "invalid_request", "Authorization type must be Bearer");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Authorization must be Bearer").captureStackTrace(false).build();
        }

        // 2) Verify & decode
        final JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(token, null);
        } catch (BadJWTException e) {
            String msg = (e.getMessage() == null ? "Invalid token" : e.getMessage());
            setWwwAuthenticate(response, "invalid_token", msg);
            throw VeggieException.builder(ProblemTypes.JWT_INVALID).detail(msg).cause(e).captureStackTrace(false).build();
        } catch (Exception e) {
            setWwwAuthenticate(response, "invalid_token", "Unable to verify token");
            throw VeggieException.builder(ProblemTypes.JWT_INVALID)
                    .detail("Unable to verify token").cause(e).captureStackTrace(false).build();
        }

        // Optional: enforce alg exactly matches expected
        try {
            String algInHeader = com.nimbusds.jwt.SignedJWT.parse(token).getHeader().getAlgorithm().getName();
            if (!expectedAlg.equals(algInHeader)) {
                setWwwAuthenticate(response, "invalid_token", "Unsupported JWS alg");
                throw VeggieException.builder(ProblemTypes.JWT_INVALID)
                        .detail("Unsupported JWS algorithm").captureStackTrace(false).build();
            }
        } catch (ParseException ignore) {
            // Already verified above; this is defensive only.
        }

        // 3) Validate issuer / audience / temporal with clock skew
        if (!Objects.equals(expectedIssuer, claims.getIssuer())) {
            setWwwAuthenticate(response, "invalid_token", "Issuer mismatch");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Invalid token issuer").captureStackTrace(false).build();
        }
        expectedAudience.ifPresent(aud -> {
            List<String> claimAud = claims.getAudience();
            if (claimAud == null || !claimAud.contains(aud)) {
                throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                        .detail("Token audience not accepted").captureStackTrace(false).build();
            }
        });
        long now = clock.instant().getEpochSecond();
        Date exp = claims.getExpirationTime();
        Date nbf = claims.getNotBeforeTime();
        if (exp != null && (exp.toInstant().getEpochSecond() + clockSkew.getSeconds()) < now) {
            setWwwAuthenticate(response, "invalid_token", "Token expired");
            throw VeggieException.builder(ProblemTypes.JWT_INVALID)
                    .detail("Token has expired").captureStackTrace(false).build();
        }
        if (nbf != null && (nbf.toInstant().getEpochSecond() - clockSkew.getSeconds()) > now) {
            setWwwAuthenticate(response, "invalid_token", "Token not yet valid");
            throw VeggieException.builder(ProblemTypes.AUTHENTICATION_FAILED)
                    .detail("Token not yet valid").captureStackTrace(false).build();
        }

        // 4) Multi-tenant guard: tenantId claim MUST match header/context when present
        String claimTenant = stringClaim(claims, "tenantId");
        if (claimTenant == null || claimTenant.isBlank()) {
            setWwwAuthenticate(response, "insufficient_scope", "tenantId claim required");
            throw VeggieException.builder(ProblemTypes.AUTHORIZATION_DENIED)
                    .detail("Missing tenantId claim").captureStackTrace(false).build();
        }
        String headerTenant = firstHeaderValue(request.getHeader(HEADER_TENANT_ID));
        TenantId ctxTenant = TenantContext.currentTenantId().orElse(null);
        String effectiveTenant = (ctxTenant != null ? ctxTenant.value() : headerTenant);
        if (effectiveTenant != null && !claimTenant.equals(effectiveTenant)) {
            setWwwAuthenticate(response, "insufficient_scope", "tenant mismatch");
            throw VeggieException.builder(ProblemTypes.TENANT_MISMATCH)
                    .detail("Tenant mismatch between token and request").captureStackTrace(false).build();
        }

        // 5) Build & expose principal (no PII logging here)
        OidcPrincipal principal = new OidcPrincipal(
                claims.getSubject(),
                claimTenant,
                stringClaim(claims, "vendorId"),
                toStringSet(claims.getClaim("roles")),
                mergeScopes(claims.getClaim("scope"), claims.getClaim("scp")),
                toStringSet(claims.getClaim("amr")),
                longClaim(claims.getClaim("auth_time"))
        );
        request.setAttribute(REQUEST_ATTR_PRINCIPAL, principal);

        try {
            chain.doFilter(request, response);
        } finally {
            request.removeAttribute(REQUEST_ATTR_PRINCIPAL);
        }
    }

    // -------------------- helpers --------------------

    private static Optional<String> extractBearer(String authHeader) {
        String v = authHeader.trim();
        int space = v.indexOf(' ');
        if (space < 0) return Optional.empty();
        String scheme = v.substring(0, space);
        String token = v.substring(space + 1).trim();
        if (!"Bearer".equalsIgnoreCase(scheme) || token.isEmpty()) return Optional.empty();
        return Optional.of(token);
    }

    private static String firstHeaderValue(String raw) {
        if (raw == null) return null;
        int comma = raw.indexOf(',');
        return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
    }

    private static void setWwwAuthenticate(HttpServletResponse res, String error, String desc) {
        String realm = "veggieshop";
        String v = "Bearer realm=\"" + realm + "\", error=\"" + error + "\", error_description=\"" + desc + "\"";
        res.setHeader("WWW-Authenticate", v);
    }

    private static String defaultJwksFromIssuer(String issuer) {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        try {
            return new URL(base + "/.well-known/jwks.json").toString();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid issuer URL");
        }
    }

    private static String get(String key) {
        String sys = System.getProperty(key);
        if (sys != null) return sys;
        return System.getenv(key.replace('.', '_').toUpperCase(Locale.ROOT));
    }

    private static String getOrDefault(String key, String def) {
        String v = get(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    private static String requireNonBlank(String v, String msg) {
        if (v == null || v.isBlank()) throw new IllegalStateException(msg);
        return v;
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object v = claims.getClaim(name);
        return (v == null) ? null : String.valueOf(v);
    }

    private static Long longClaim(Object v) {
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s) try {
            return Long.parseLong(s);
        } catch (NumberFormatException ignore) {
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Set<String> toStringSet(Object v) {
        if (v == null) return Set.of();
        if (v instanceof String s) {
            return Arrays.stream(s.split("[\\s,]+")).map(String::trim).filter(x -> !x.isBlank()).collect(Collectors.toSet());
        }
        if (v instanceof Collection<?> c) {
            return c.stream().filter(Objects::nonNull).map(Object::toString).collect(Collectors.toSet());
        }
        return Set.of();
    }

    private static Set<String> mergeScopes(Object scope, Object scp) {
        Set<String> out = new LinkedHashSet<>();
        out.addAll(toStringSet(scope)); // space-delimited "scope"
        out.addAll(toStringSet(scp));   // array "scp"
        return out;
    }

    /**
     * Immutable principal exposed to downstream code.
     */
    public static final class OidcPrincipal {
        private final String subject;
        private final String tenantId;
        private final String vendorId;
        private final Set<String> roles;
        private final Set<String> scopes;
        private final Set<String> amr;
        private final Long authTimeEpochSeconds;

        public OidcPrincipal(String subject, String tenantId, String vendorId,
                             Set<String> roles, Set<String> scopes, Set<String> amr, Long authTimeEpochSeconds) {
            this.subject = subject;
            this.tenantId = tenantId;
            this.vendorId = vendorId;
            this.roles = (roles == null ? Set.of() : Set.copyOf(roles));
            this.scopes = (scopes == null ? Set.of() : Set.copyOf(scopes));
            this.amr = (amr == null ? Set.of() : Set.copyOf(amr));
            this.authTimeEpochSeconds = authTimeEpochSeconds;
        }

        public String subject() {
            return subject;
        }

        public String tenantId() {
            return tenantId;
        }

        public Optional<String> vendorId() {
            return Optional.ofNullable(vendorId);
        }

        public Set<String> roles() {
            return roles;
        }

        public Set<String> scopes() {
            return scopes;
        }

        public Set<String> amr() {
            return amr;
        }

        public Optional<Long> authTimeEpochSeconds() {
            return Optional.ofNullable(authTimeEpochSeconds);
        }
    }
}
