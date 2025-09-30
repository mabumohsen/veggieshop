package io.veggieshop.platform.starter.observability.web.autoconfig;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Prefix: veggieshop.web.observability.pii-log */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.observability.pii-log")
public class PiiLogWebProperties {

  /** Master switch for the PII log guard. */
  private boolean enabled = true;

  /** Maximum chars from request payload to be considered for logging/sanitizing. */
  @Min(0)
  private int payloadMaxChars = 2000;

  /** Headers never printed to logs (case-insensitive behavior handled in filter). */
  @NotNull
  private Set<String> headerDenylist =
      new LinkedHashSet<>(
          Set.of(
              "Authorization",
              "Proxy-Authorization",
              "Cookie",
              "Set-Cookie",
              "X-Api-Key",
              "X-Auth-Token"));

  /**
   * Regex patterns to redact from logs. Keep conservative, non-catastrophic patterns. Examples
   * include emails, 16-digit cards (loose), and 'password=' style assignments.
   */
  @NotNull
  private List<String> redactPatterns =
      new ArrayList<>(
          List.of(
              "(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
              "\\b(?:\\d[ -]*?){13,19}\\b", "(?i)(password|passwd|pwd)\\s*[:=]\\s*[^&\\s]+"));

  // Getters / Setters
  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public int getPayloadMaxChars() {
    return payloadMaxChars;
  }

  public void setPayloadMaxChars(int payloadMaxChars) {
    this.payloadMaxChars = payloadMaxChars;
  }

  /** Defensive view to avoid exposing internal representation. */
  public Set<String> getHeaderDenylist() {
    return Collections.unmodifiableSet(headerDenylist);
  }

  public void setHeaderDenylist(Set<String> headerDenylist) {
    this.headerDenylist =
        (headerDenylist == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(headerDenylist);
  }

  /** Defensive view to avoid exposing internal representation. */
  public List<String> getRedactPatterns() {
    return Collections.unmodifiableList(redactPatterns);
  }

  public void setRedactPatterns(List<String> redactPatterns) {
    this.redactPatterns =
        (redactPatterns == null) ? new ArrayList<>() : new ArrayList<>(redactPatterns);
  }
}
