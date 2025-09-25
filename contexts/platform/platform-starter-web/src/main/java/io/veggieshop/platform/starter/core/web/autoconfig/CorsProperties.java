package io.veggieshop.platform.starter.core.web.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/** Prefix: veggieshop.web.cors */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.cors")
public class CorsProperties {
    private boolean enabled = false;

    private Set<String> allowedOrigins = new LinkedHashSet<>(Set.of("*"));
    private Set<String> allowedMethods  = new LinkedHashSet<>(Set.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
    private Set<String> allowedHeaders  = new LinkedHashSet<>(Set.of("*"));
    private Set<String> exposedHeaders  = new LinkedHashSet<>();
    private boolean allowCredentials = false;
    private Duration maxAge = Duration.ofMinutes(30);

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Set<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(Set<String> allowedOrigins) { this.allowedOrigins = new LinkedHashSet<>(allowedOrigins); }

    public Set<String> getAllowedMethods() { return allowedMethods; }
    public void setAllowedMethods(Set<String> allowedMethods) { this.allowedMethods = new LinkedHashSet<>(allowedMethods); }

    public Set<String> getAllowedHeaders() { return allowedHeaders; }
    public void setAllowedHeaders(Set<String> allowedHeaders) { this.allowedHeaders = new LinkedHashSet<>(allowedHeaders); }

    public Set<String> getExposedHeaders() { return exposedHeaders; }
    public void setExposedHeaders(Set<String> exposedHeaders) { this.exposedHeaders = new LinkedHashSet<>(exposedHeaders); }

    public boolean isAllowCredentials() { return allowCredentials; }
    public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }

    public Duration getMaxAge() { return maxAge; }
    public void setMaxAge(Duration maxAge) { this.maxAge = maxAge; }
}
