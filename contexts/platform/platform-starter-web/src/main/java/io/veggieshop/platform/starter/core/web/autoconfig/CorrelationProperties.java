package io.veggieshop.platform.starter.core.web.autoconfig;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Correlation ID settings (prefix: {@code veggieshop.web.correlation}).
 *
 * <p>Controls header name, generation strategy, and MDC key.
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.correlation")
public class CorrelationProperties {

  /**
   * Correlation ID generator types.
   *
   * <ul>
   *   <li>{@code UUID}: random v4 UUID.
   *   <li>{@code ULID}: lexicographically sortable.
   *   <li>{@code TRACE_ID}: 16-byte hex compatible with W3C trace id.
   * </ul>
   */
  public enum Generator {
    UUID,
    ULID,
    TRACE_ID
  }

  private boolean enabled = true;

  @NotBlank private String header = "X-Correlation-Id";

  private boolean generateIfMissing = true;

  private Generator generator = Generator.UUID;

  @NotBlank private String mdcKey = "correlationId";

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getHeader() {
    return header;
  }

  public void setHeader(String header) {
    this.header = header;
  }

  public boolean isGenerateIfMissing() {
    return generateIfMissing;
  }

  public void setGenerateIfMissing(boolean generateIfMissing) {
    this.generateIfMissing = generateIfMissing;
  }

  public Generator getGenerator() {
    return generator;
  }

  public void setGenerator(Generator generator) {
    this.generator = (generator == null) ? Generator.UUID : generator;
  }

  public String getMdcKey() {
    return mdcKey;
  }

  public void setMdcKey(String mdcKey) {
    this.mdcKey = mdcKey;
  }
}
