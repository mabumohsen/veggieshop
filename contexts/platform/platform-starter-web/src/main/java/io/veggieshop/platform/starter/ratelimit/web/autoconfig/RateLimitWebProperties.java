package io.veggieshop.platform.starter.ratelimit.web.autoconfig;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Prefix: {@code veggieshop.web.ratelimit}.
 *
 * <p>Configures the rate-limit filter with flexible key strategies and default/per-path policies.
 * DTOs are bound from configuration and converted to filter policies in the auto-configuration.
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.ratelimit")
public class RateLimitWebProperties {

  /** Master switch. */
  private boolean enabled = true;

  /** Emit RFC 9239 headers. */
  private boolean headers = true;

  /** Key strategy (order matters). Examples: "tenant", "ip", "path", "header:X-API-Key". */
  @NotEmpty private List<String> keys = new ArrayList<>(List.of("tenant", "ip"));

  /** Default bucket policy. */
  @Valid @NotNull private RateLimitPolicyProps defaultPolicy = RateLimitPolicyProps.defaults();

  /**
   * Per-path overrides (ANT style).
   *
   * <pre>
   * overrides:
   *   "/api/public/**": { capacity: 1000, refill-tokens: 1000, refill-period: 1m }
   * </pre>
   */
  @Valid private Map<String, RateLimitPolicyProps> overrides = new LinkedHashMap<>();

  /** Advanced: max unique buckets (in-memory). */
  @Min(1)
  private int maxBuckets = 200_000;

  /** Advanced: evict idle buckets after this duration. */
  @NotNull private Duration idleEvictAfter = Duration.ofMinutes(15);

  /** Policy DTO bound from configuration. */
  @Validated
  public static class RateLimitPolicyProps {
    @Min(1)
    private long capacity = 100;

    @Min(1)
    private long refillTokens = 100;

    @NotNull private Duration refillPeriod = Duration.ofMinutes(1);

    public RateLimitPolicyProps() {}

    /** Defensive copy constructor. */
    public RateLimitPolicyProps(RateLimitPolicyProps other) {
      this.capacity = other.capacity;
      this.refillTokens = other.refillTokens;
      this.refillPeriod = other.refillPeriod; // Duration is immutable
    }

    public static RateLimitPolicyProps defaults() {
      return new RateLimitPolicyProps();
    }

    public long getCapacity() {
      return capacity;
    }

    public void setCapacity(long capacity) {
      this.capacity = capacity;
    }

    public long getRefillTokens() {
      return refillTokens;
    }

    public void setRefillTokens(long refillTokens) {
      this.refillTokens = refillTokens;
    }

    public Duration getRefillPeriod() {
      return refillPeriod;
    }

    public void setRefillPeriod(Duration refillPeriod) {
      this.refillPeriod = refillPeriod;
    }
  }

  // --- Getters / Setters ---

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isHeaders() {
    return headers;
  }

  public void setHeaders(boolean headers) {
    this.headers = headers;
  }

  /** Unmodifiable view to avoid exposing internal representation. */
  public List<String> getKeys() {
    return java.util.Collections.unmodifiableList(keys);
  }

  public void setKeys(List<String> keys) {
    this.keys = (keys == null) ? new ArrayList<>() : new ArrayList<>(keys);
  }

  /** Defensive copy to avoid exposing internal representation. */
  public RateLimitPolicyProps getDefaultPolicy() {
    return new RateLimitPolicyProps(defaultPolicy);
  }

  /**
   * Sets the default rate-limit policy. Stores a defensive copy to avoid external mutation.
   *
   * @param defaultPolicy policy to use when no path override matches; if {@code null}, a sensible
   *     default is used
   */
  public void setDefaultPolicy(RateLimitPolicyProps defaultPolicy) {
    this.defaultPolicy =
        (defaultPolicy == null)
            ? RateLimitPolicyProps.defaults()
            : new RateLimitPolicyProps(defaultPolicy);
  }

  /** Unmodifiable view to avoid exposing internal representation. */
  public Map<String, RateLimitPolicyProps> getOverrides() {
    return java.util.Collections.unmodifiableMap(overrides);
  }

  /**
   * Sets per-path policy overrides (ANT patterns). A defensive copy is stored while preserving
   * insertion order.
   *
   * @param overrides map of path pattern to policy; if {@code null}, an empty map is used
   */
  public void setOverrides(Map<String, RateLimitPolicyProps> overrides) {
    if (overrides == null) {
      this.overrides = new LinkedHashMap<>();
      return;
    }
    this.overrides = new LinkedHashMap<>();
    overrides.forEach(
        (k, v) ->
            this.overrides.put(
                k, v == null ? RateLimitPolicyProps.defaults() : new RateLimitPolicyProps(v)));
  }

  public int getMaxBuckets() {
    return maxBuckets;
  }

  public void setMaxBuckets(int maxBuckets) {
    this.maxBuckets = maxBuckets;
  }

  public Duration getIdleEvictAfter() {
    return idleEvictAfter;
  }

  public void setIdleEvictAfter(Duration idleEvictAfter) {
    this.idleEvictAfter = idleEvictAfter;
  }
}
