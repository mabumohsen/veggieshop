package io.veggieshop.platform.starter.tenancy;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

/**
 * Tenancy web properties.
 * Prefix: veggieshop.web.tenancy
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.tenancy")
public class WebTenancyProperties {

    /** Master switch for the TenantFilter. */
    private boolean enabled = true;

    /** HTTP header used to resolve the tenant id (default matches TenantContext.REQUEST_HEADER). */
    @NotBlank
    private String header = "X-Tenant-Id";

    /** Reject requests without a tenant id (except for public paths / allowlist). */
    private boolean required = true;

    /** Ant-style public paths that bypass tenant requirement (e.g., health/actuator/docs). */
    private List<String> publicPaths = new ArrayList<>(List.of(
            "/health/**", "/actuator/**"
    ));

    /** MDC key to mirror the tenant id under (defaults to 'tenantId'). */
    @NotBlank
    private String mdcKey = "tenantId";

    // Getters / Setters
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getHeader() { return header; }
    public void setHeader(String header) { this.header = header; }

    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = (publicPaths == null) ? new ArrayList<>() : new ArrayList<>(publicPaths);
    }

    public String getMdcKey() { return mdcKey; }
    public void setMdcKey(String mdcKey) { this.mdcKey = mdcKey; }
}
