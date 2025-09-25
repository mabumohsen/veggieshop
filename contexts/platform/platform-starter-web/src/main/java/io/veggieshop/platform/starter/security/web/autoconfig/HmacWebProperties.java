package io.veggieshop.platform.starter.security.web.autoconfig;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Prefix: veggieshop.web.hmac
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.hmac")
public class HmacWebProperties {

    /** Master switch handled by @ConditionalOnProperty on the auto-config. */
    private boolean enabled = false;

    /** Header carrying the key id (kid). */
    @NotBlank
    private String keyIdHeader = "X-HMAC-Key-Id";

    /** Header carrying the unix-epoch timestamp (seconds or millis per your filter). */
    @NotBlank
    private String timestampHeader = "X-HMAC-Timestamp";

    /** Header carrying the unique nonce. */
    @NotBlank
    private String nonceHeader = "X-HMAC-Nonce";

    /** Header carrying the computed signature. */
    @NotBlank
    private String signatureHeader = "X-HMAC-Signature";

    /** Accepted HMAC algorithms (e.g., HmacSHA256, HmacSHA512). First entry is used. */
    @NotNull
    private List<String> acceptedAlgorithms = new ArrayList<>(List.of("HmacSHA256"));

    /** Maximum request body bytes to include in MAC; larger bodies will be rejected (413). */
    @Min(0)
    private int maxBodyBytes = 1_000_000; // 1 MB

    /** Allowed clock skew when validating timestamps. */
    @NotNull
    private Duration clockSkew = Duration.ofMinutes(1);

    /** Nonce TTL (window where a nonce cannot be reused). */
    @NotNull
    private Duration ttl = Duration.ofMinutes(10);

    /** Default in-memory nonce cache size (used only if the app doesn't provide a NonceStore bean). */
    @Min(1)
    private int nonceCacheSize = 500_000;

    /** Enforce body SHA-256 header/payload requirement. */
    private boolean enforceBodySha256 = false;

    /** Optional explicit filter order; if null, defaults to (TenantFilter.ORDER + 15). */
    private Integer order;

    // Getters / Setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getKeyIdHeader() { return keyIdHeader; }
    public void setKeyIdHeader(String keyIdHeader) { this.keyIdHeader = keyIdHeader; }

    public String getTimestampHeader() { return timestampHeader; }
    public void setTimestampHeader(String timestampHeader) { this.timestampHeader = timestampHeader; }

    public String getNonceHeader() { return nonceHeader; }
    public void setNonceHeader(String nonceHeader) { this.nonceHeader = nonceHeader; }

    public String getSignatureHeader() { return signatureHeader; }
    public void setSignatureHeader(String signatureHeader) { this.signatureHeader = signatureHeader; }

    public List<String> getAcceptedAlgorithms() { return acceptedAlgorithms; }
    public void setAcceptedAlgorithms(List<String> acceptedAlgorithms) {
        this.acceptedAlgorithms = (acceptedAlgorithms == null) ? new ArrayList<>() : new ArrayList<>(acceptedAlgorithms);
    }

    public int getMaxBodyBytes() { return maxBodyBytes; }
    public void setMaxBodyBytes(int maxBodyBytes) { this.maxBodyBytes = maxBodyBytes; }

    public Duration getClockSkew() { return clockSkew; }
    public void setClockSkew(Duration clockSkew) { this.clockSkew = clockSkew; }

    public Duration getTtl() { return ttl; }
    public void setTtl(Duration ttl) { this.ttl = ttl; }

    public int getNonceCacheSize() { return nonceCacheSize; }
    public void setNonceCacheSize(int nonceCacheSize) { this.nonceCacheSize = nonceCacheSize; }

    public boolean isEnforceBodySha256() { return enforceBodySha256; }
    public void setEnforceBodySha256(boolean enforceBodySha256) { this.enforceBodySha256 = enforceBodySha256; }

    public Integer getOrder() { return order; }
    public void setOrder(Integer order) { this.order = order; }
}
