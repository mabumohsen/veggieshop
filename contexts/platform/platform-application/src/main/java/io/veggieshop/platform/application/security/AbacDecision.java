// AbacDecision.java
package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;

import java.util.Set;

/** ABAC authorization decision with optional obligations. */
public record AbacDecision(
        @NotNull Effect effect,
        @NotNull String reason,
        Set<AbacObligation> obligations
) {
    public AbacDecision {
        obligations = obligations == null ? Set.of() : Set.copyOf(obligations);
    }

    public static AbacDecision permit(String reason) {
        return new AbacDecision(Effect.PERMIT, reason, Set.of());
    }

    public static AbacDecision deny(String reason) {
        return new AbacDecision(Effect.DENY, reason, Set.of());
    }

    public static AbacDecision challenge(String reason, Set<AbacObligation> obligations) {
        return new AbacDecision(Effect.CHALLENGE, reason,
                obligations == null ? Set.of() : Set.copyOf(obligations));
    }

    /** Authorization decision effect. */
    public enum Effect { PERMIT, DENY, CHALLENGE }
}
