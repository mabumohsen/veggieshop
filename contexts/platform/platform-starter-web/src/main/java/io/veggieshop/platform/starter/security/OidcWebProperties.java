package io.veggieshop.platform.starter.security;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Prefix: veggieshop.web.oidc
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.oidc")
public class OidcWebProperties {

    /** Master switch handled by @ConditionalOnProperty on the auto-config. */
    private boolean enabled = false;

    /** Preferred: issuer URL (e.g., https://login.example.com/realms/veggie). */
    private String issuer;

    /** Optional explicit JWKS URI; if empty, derived from issuer (/.well-known/jwks.json). */
    private String jwksUri;

    /** Accepted JWS algorithms (e.g., RS256, ES256). First entry is used to create selector. */
    @NotNull
    private List<String> allowedAlgs = new ArrayList<>(List.of("RS256"));

    /** Expected audience claims; empty = skip audience check in filter. */
    @NotNull
    private Set<String> audience = new LinkedHashSet<>();

    /** Public (unauthenticated) paths that the filter should skip (ant style). */
    @NotNull
    private List<String> publicPaths = new ArrayList<>(List.of(
            "/health/**", "/actuator/**"
    ));

    /** Allowed clock skew for JWT validation. */
    @NotNull
    private Duration clockSkew = Duration.ofMinutes(2);

    /** JWKS connect timeout. */
    @NotNull
    private Duration jwksConnectTimeout = Duration.ofSeconds(2);

    /** JWKS read timeout. */
    @NotNull
    private Duration jwksReadTimeout = Duration.ofSeconds(3);

    /** Max JWKS payload size (bytes). */
    @Min(1024)
    private int jwksSizeLimitBytes = 50_000;

    /** Optional explicit filter order; null = default. */
    private Integer order;

    // Getters/Setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public List<String> getAllowedAlgs() { return allowedAlgs; }
    public void setAllowedAlgs(List<String> allowedAlgs) {
        this.allowedAlgs = (allowedAlgs == null) ? new ArrayList<>() : new ArrayList<>(allowedAlgs);
    }

    public Set<String> getAudience() { return audience; }
    public void setAudience(Set<String> audience) {
        this.audience = (audience == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(audience);
    }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = (publicPaths == null) ? new ArrayList<>() : new ArrayList<>(publicPaths);
    }

    public Duration getClockSkew() { return clockSkew; }
    public void setClockSkew(Duration clockSkew) { this.clockSkew = clockSkew; }

    public Duration getJwksConnectTimeout() { return jwksConnectTimeout; }
    public void setJwksConnectTimeout(Duration jwksConnectTimeout) { this.jwksConnectTimeout = jwksConnectTimeout; }

    public Duration getJwksReadTimeout() { return jwksReadTimeout; }
    public void setJwksReadTimeout(Duration jwksReadTimeout) { this.jwksReadTimeout = jwksReadTimeout; }

    public int getJwksSizeLimitBytes() { return jwksSizeLimitBytes; }
    public void setJwksSizeLimitBytes(int jwksSizeLimitBytes) { this.jwksSizeLimitBytes = jwksSizeLimitBytes; }

    public Integer getOrder() { return order; }
    public void setOrder(Integer order) { this.order = order; }
}
