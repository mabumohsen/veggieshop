package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;
import java.util.Set;

/**
 * ABAC authorization decision with optional obligations.
 *
 * @param effect the decision effect ({@link Effect#PERMIT}, {@link Effect#DENY}, or {@link
 *     Effect#CHALLENGE})
 * @param reason short explanation for the decision (no PII)
 * @param obligations obligations the caller must satisfy when {@code effect} is {@link
 *     Effect#CHALLENGE}; may be {@code null}, which is treated as an empty set
 */
public record AbacDecision(
    @NotNull Effect effect, @NotNull String reason, Set<AbacObligation> obligations) {

  /** Canonical compact constructor that normalizes {@code obligations} to an unmodifiable set. */
  public AbacDecision {
    obligations = (obligations == null) ? Set.of() : Set.copyOf(obligations);
  }

  /** Returns a PERMIT decision with no obligations. */
  public static AbacDecision permit(String reason) {
    return new AbacDecision(Effect.PERMIT, reason, Set.of());
  }

  /** Returns a DENY decision with no obligations. */
  public static AbacDecision deny(String reason) {
    return new AbacDecision(Effect.DENY, reason, Set.of());
  }

  /**
   * Returns a CHALLENGE decision with optional obligations.
   *
   * @param reason short explanation for the challenge
   * @param obligations obligations to be satisfied (nullable; treated as empty if {@code null})
   */
  public static AbacDecision challenge(String reason, Set<AbacObligation> obligations) {
    return new AbacDecision(
        Effect.CHALLENGE, reason, (obligations == null) ? Set.of() : Set.copyOf(obligations));
  }

  /** Authorization decision effect. */
  public enum Effect {
    PERMIT,
    DENY,
    CHALLENGE
  }
}
