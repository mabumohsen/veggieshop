package io.veggieshop.platform.starter.core;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Locale;

/** Prefix: veggieshop.web.correlation */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.correlation")
public class CorrelationProperties {

    public enum Generator {
        UUID,      // java.util.UUID random v4
        ULID,      // lexicographically sortable
        TRACE_ID   // 16-byte hex (matches W3C trace id)
    }

    private boolean enabled = true;

    @NotBlank
    private String header = "X-Correlation-Id";

    private boolean generateIfMissing = true;

    private Generator generator = Generator.UUID;

    @NotBlank
    private String mdcKey = "correlationId";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getHeader() { return header; }
    public void setHeader(String header) { this.header = header; }

    public boolean isGenerateIfMissing() { return generateIfMissing; }
    public void setGenerateIfMissing(boolean generateIfMissing) { this.generateIfMissing = generateIfMissing; }

    public Generator getGenerator() { return generator; }
    public void setGenerator(Generator generator) { this.generator = generator; }

    public String getMdcKey() { return mdcKey; }
    public void setMdcKey(String mdcKey) { this.mdcKey = mdcKey; }
}
