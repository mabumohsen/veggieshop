package io.veggieshop.platform.starter.security.web.autoconfig;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Prefix: veggieshop.web.step-up */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.step-up")
public class StepUpWebProperties {

  /** Master switch handled by @ConditionalOnProperty on the auto-config. */
  private boolean enabled = false;

  /** Default maximum age for MFA freshness when @RequireStepUp has no explicit maxAgeSeconds. */
  @NotNull private Duration defaultMaxAge = Duration.ofMinutes(5);

  /**
   * AMR hints that qualify as MFA (case-insensitive): e.g., "mfa","otp","totp","webauthn","hwk".
   */
  @NotNull
  private Set<String> mfaAmrHints =
      new LinkedHashSet<>(Set.of("mfa", "otp", "totp", "webauthn", "hwk", "sms"));

  /** Whether HMAC principals are allowed to satisfy step-up via elevation store (not via AMR). */
  private boolean allowHmacPrincipals = false;

  /** Optional explicit interceptor order; null = use StepUpInterceptor.ORDER. */
  private Integer order;

  // Getters / Setters
  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public Duration getDefaultMaxAge() {
    return defaultMaxAge;
  }

  public void setDefaultMaxAge(Duration defaultMaxAge) {
    this.defaultMaxAge = defaultMaxAge;
  }

  /** Unmodifiable view to avoid exposing internal representation. */
  public Set<String> getMfaAmrHints() {
    return Collections.unmodifiableSet(mfaAmrHints);
  }

  public void setMfaAmrHints(Set<String> mfaAmrHints) {
    this.mfaAmrHints =
        (mfaAmrHints == null) ? new LinkedHashSet<>() : new LinkedHashSet<>(mfaAmrHints);
  }

  public boolean isAllowHmacPrincipals() {
    return allowHmacPrincipals;
  }

  public void setAllowHmacPrincipals(boolean allowHmacPrincipals) {
    this.allowHmacPrincipals = allowHmacPrincipals;
  }

  public Integer getOrder() {
    return order;
  }

  public void setOrder(Integer order) {
    this.order = order;
  }
}
