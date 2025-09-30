package io.veggieshop.platform.starter.core.web.autoconfig;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * CORS configuration (prefix: {@code veggieshop.web.cors}).
 *
 * <p>Provides defensive copies in getters and null-safe setters to avoid exposing internal state.
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.cors")
public class CorsProperties {
  private boolean enabled = false;

  private Set<String> allowedOrigins = new LinkedHashSet<>(Set.of("*"));
  private Set<String> allowedMethods =
      new LinkedHashSet<>(Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
  private Set<String> allowedHeaders = new LinkedHashSet<>(Set.of("*"));
  private Set<String> exposedHeaders = new LinkedHashSet<>();
  private boolean allowCredentials = false;
  private Duration maxAge = Duration.ofMinutes(30);

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  /** Returns an unmodifiable copy of allowed origins. */
  public Set<String> getAllowedOrigins() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(allowedOrigins));
  }

  public void setAllowedOrigins(Set<String> allowedOrigins) {
    this.allowedOrigins =
        (allowedOrigins == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(allowedOrigins);
  }

  /** Returns an unmodifiable copy of allowed methods. */
  public Set<String> getAllowedMethods() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(allowedMethods));
  }

  public void setAllowedMethods(Set<String> allowedMethods) {
    this.allowedMethods =
        (allowedMethods == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(allowedMethods);
  }

  /** Returns an unmodifiable copy of allowed headers. */
  public Set<String> getAllowedHeaders() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(allowedHeaders));
  }

  public void setAllowedHeaders(Set<String> allowedHeaders) {
    this.allowedHeaders =
        (allowedHeaders == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(allowedHeaders);
  }

  /** Returns an unmodifiable copy of exposed headers. */
  public Set<String> getExposedHeaders() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(exposedHeaders));
  }

  public void setExposedHeaders(Set<String> exposedHeaders) {
    this.exposedHeaders =
        (exposedHeaders == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(exposedHeaders);
  }

  public boolean isAllowCredentials() {
    return allowCredentials;
  }

  public void setAllowCredentials(boolean allowCredentials) {
    this.allowCredentials = allowCredentials;
  }

  public Duration getMaxAge() {
    return maxAge;
  }

  public void setMaxAge(Duration maxAge) {
    this.maxAge = (maxAge == null) ? Duration.ofMinutes(30) : maxAge;
  }
}
