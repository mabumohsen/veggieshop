package io.veggieshop.platform.starter.ratelimit;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.*;

/**
 * Prefix: {@code veggieshop.web.ratelimit}
 *
 * يضبط مُرشّح الحدّ من المعدّل (RateLimitFilter) بمفاتيح مرنة وسياسات افتراضية/لكل مسار.
 * نستخدم DTOs قابلة للربط ثم نحوّلها إلى Policy داخل الـ AutoConfiguration.
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.ratelimit")
public class RateLimitWebProperties {

    /** Master switch. */
    private boolean enabled = true;

    /** Emit RFC 9239 headers. */
    private boolean headers = true;

    /**
     * Key strategy (order matters). Examples:
     *  - "tenant"
     *  - "ip"
     *  - "path"
     *  - "header:X-API-Key"
     */
    @NotEmpty
    private List<String> keys = new ArrayList<>(List.of("tenant", "ip"));

    /** Default bucket policy. */
    @Valid @NotNull
    private RateLimitPolicyProps defaultPolicy = RateLimitPolicyProps.defaults();

    /**
     * Per-path overrides (ANT style):
     *   overrides:
     *     "/api/public/**": { capacity: 1000, refill-tokens: 1000, refill-period: 1m }
     */
    @Valid
    private Map<String, RateLimitPolicyProps> overrides = new LinkedHashMap<>();

    /** Advanced: max unique buckets (in-memory). */
    @Min(1)
    private int maxBuckets = 200_000;

    /** Advanced: evict idle buckets after this duration. */
    @NotNull
    private Duration idleEvictAfter = Duration.ofMinutes(15);

    // --- DTO for YAML binding ---
    @Validated
    public static class RateLimitPolicyProps {
        @Min(1) private long capacity = 100;
        @Min(1) private long refillTokens = 100;
        @NotNull private Duration refillPeriod = Duration.ofMinutes(1);

        public static RateLimitPolicyProps defaults() { return new RateLimitPolicyProps(); }

        public long getCapacity() { return capacity; }
        public void setCapacity(long capacity) { this.capacity = capacity; }

        public long getRefillTokens() { return refillTokens; }
        public void setRefillTokens(long refillTokens) { this.refillTokens = refillTokens; }

        public Duration getRefillPeriod() { return refillPeriod; }
        public void setRefillPeriod(Duration refillPeriod) { this.refillPeriod = refillPeriod; }
    }

    // --- Getters / Setters ---

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isHeaders() { return headers; }
    public void setHeaders(boolean headers) { this.headers = headers; }

    public List<String> getKeys() { return keys; }
    public void setKeys(List<String> keys) {
        this.keys = (keys == null) ? new ArrayList<>() : new ArrayList<>(keys);
    }

    public RateLimitPolicyProps getDefaultPolicy() { return defaultPolicy; }
    public void setDefaultPolicy(RateLimitPolicyProps defaultPolicy) { this.defaultPolicy = defaultPolicy; }

    public Map<String, RateLimitPolicyProps> getOverrides() { return overrides; }
    public void setOverrides(Map<String, RateLimitPolicyProps> overrides) {
        this.overrides = (overrides == null) ? new LinkedHashMap<>() : new LinkedHashMap<>(overrides);
    }

    public int getMaxBuckets() { return maxBuckets; }
    public void setMaxBuckets(int maxBuckets) { this.maxBuckets = maxBuckets; }

    public Duration getIdleEvictAfter() { return idleEvictAfter; }
    public void setIdleEvictAfter(Duration idleEvictAfter) { this.idleEvictAfter = idleEvictAfter; }
}
