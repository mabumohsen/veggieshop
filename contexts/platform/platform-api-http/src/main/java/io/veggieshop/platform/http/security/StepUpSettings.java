package io.veggieshop.platform.http.security;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable settings for the step-up (stronger authentication) policy enforced by the platform.
 *
 * <p>Typical usage is to bind this from configuration in the starter and inject it into the HTTP
 * layer (interceptors/filters) that perform step-up checks.
 */
public final class StepUpSettings {
  private final Duration defaultMaxAge; // e.g. PT5M
  private final Set<String> mfaAmrHints; // e.g. mfa, otp, webauthn, u2f, totp
  private final boolean allowHmacPrincipals; // whether HMAC traffic can ever satisfy step-up

  /**
   * Creates a new immutable settings instance.
   *
   * @param defaultMaxAge maximum acceptable age for an MFA/AMR event; defaults to 5 minutes if null
   *     or negative
   * @param mfaAmrHints set of AMR/MFA hints (case-insensitive); defaults to a conservative built-in
   *     set if null/empty
   * @param allowHmacPrincipals whether HMAC-authenticated traffic can satisfy step-up
   */
  public StepUpSettings(
      Duration defaultMaxAge, Set<String> mfaAmrHints, boolean allowHmacPrincipals) {
    this.defaultMaxAge =
        (defaultMaxAge == null || defaultMaxAge.isNegative())
            ? Duration.ofMinutes(5)
            : defaultMaxAge;

    // Normalize to lowercase for robust matching; store as unmodifiable
    Set<String> base =
        (mfaAmrHints == null || mfaAmrHints.isEmpty())
            ? Set.of("mfa", "otp", "sms", "email", "hwk", "webauthn", "u2f", "totp")
            : mfaAmrHints;

    this.mfaAmrHints =
        base.stream()
            .filter(Objects::nonNull)
            .map(s -> s.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());

    this.allowHmacPrincipals = allowHmacPrincipals;
  }

  /**
   * Returns the default maximum acceptable age for an MFA/AMR event.
   *
   * @return the default maximum acceptable age for an MFA/AMR event
   */
  public Duration defaultMaxAge() {
    return defaultMaxAge;
  }

  /**
   * Returns the configured AMR/MFA hints as an unmodifiable copy.
   *
   * <p>This provides a defensive copy to avoid representation exposure.
   *
   * @return an unmodifiable copy of the AMR/MFA hint set
   */
  public Set<String> mfaAmrHints() {
    // Defensive copy to satisfy SpotBugs (EI_EXPOSE_REP)
    return Set.copyOf(mfaAmrHints);
  }

  /**
   * Indicates whether HMAC-authenticated principals are allowed to satisfy step-up requirements.
   *
   * @return true if HMAC-authenticated principals are allowed; false otherwise
   */
  public boolean allowHmacPrincipals() {
    return allowHmacPrincipals;
  }

  /** Builder for {@link StepUpSettings} to enable fluent assembly in auto-configuration. */
  public static final class Builder {
    private Duration defaultMaxAge = Duration.ofMinutes(5);
    private final Set<String> mfaAmrHints = new LinkedHashSet<>();
    private boolean allowHmacPrincipals = false;

    /**
     * Sets the default maximum acceptable age for MFA/AMR events.
     *
     * @param v the duration (e.g., {@code PT5M})
     * @return this builder
     */
    public Builder defaultMaxAge(Duration v) {
      this.defaultMaxAge = v;
      return this;
    }

    /**
     * Replaces the entire set of AMR/MFA hints.
     *
     * @param v a set of hint strings; null clears to defaults at build time
     * @return this builder
     */
    public Builder mfaAmrHints(Set<String> v) {
      this.mfaAmrHints.clear();
      if (v != null) {
        this.mfaAmrHints.addAll(v);
      }
      return this;
    }

    /**
     * Configures whether HMAC-authenticated principals can satisfy step-up.
     *
     * @param v true to allow; false to disallow
     * @return this builder
     */
    public Builder allowHmacPrincipals(boolean v) {
      this.allowHmacPrincipals = v;
      return this;
    }

    /**
     * Builds an immutable {@link StepUpSettings}.
     *
     * @return the immutable settings instance
     */
    public StepUpSettings build() {
      // Pass null to pick up class defaults if no hints were provided
      Set<String> hints = (mfaAmrHints.isEmpty() ? null : mfaAmrHints);
      return new StepUpSettings(defaultMaxAge, hints, allowHmacPrincipals);
    }
  }
}
