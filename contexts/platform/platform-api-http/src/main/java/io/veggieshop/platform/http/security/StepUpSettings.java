package io.veggieshop.platform.http.security;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Immutable settings for StepUpInterceptor (to be built from your properties in starter-web). */
public final class StepUpSettings {
    private final Duration defaultMaxAge;          // e.g. PT5M
    private final Set<String> mfaAmrHints;         // e.g. mfa, otp, webauthn, u2f, totp
    private final boolean allowHmacPrincipals;     // whether HMAC traffic can ever satisfy step-up

    public StepUpSettings(Duration defaultMaxAge, Set<String> mfaAmrHints, boolean allowHmacPrincipals) {
        this.defaultMaxAge = (defaultMaxAge == null || defaultMaxAge.isNegative() ? Duration.ofMinutes(5) : defaultMaxAge);
        // Normalize to lowercase for robust matching
        Set<String> base = (mfaAmrHints == null || mfaAmrHints.isEmpty())
                ? Set.of("mfa","otp","sms","email","hwk","webauthn","u2f","totp")
                : mfaAmrHints;
        this.mfaAmrHints = base.stream().filter(Objects::nonNull)
                .map(s -> s.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.allowHmacPrincipals = allowHmacPrincipals;
    }

    public Duration defaultMaxAge() { return defaultMaxAge; }
    public Set<String> mfaAmrHints() { return mfaAmrHints; }
    public boolean allowHmacPrincipals() { return allowHmacPrincipals; }

    /** Builder for convenience if you prefer mutable assembly in auto-config. */
    public static final class Builder {
        private Duration defaultMaxAge = Duration.ofMinutes(5);
        private final Set<String> mfaAmrHints = new LinkedHashSet<>();
        private boolean allowHmacPrincipals = false;

        public Builder defaultMaxAge(Duration v) { this.defaultMaxAge = v; return this; }
        public Builder mfaAmrHints(Set<String> v) { this.mfaAmrHints.clear(); if (v!=null) this.mfaAmrHints.addAll(v); return this; }
        public Builder allowHmacPrincipals(boolean v) { this.allowHmacPrincipals = v; return this; }
        public StepUpSettings build() {
            // Pass null to get defaults if empty
            Set<String> hints = (mfaAmrHints.isEmpty() ? null : mfaAmrHints);
            return new StepUpSettings(defaultMaxAge, hints, allowHmacPrincipals);
        }
    }
}
