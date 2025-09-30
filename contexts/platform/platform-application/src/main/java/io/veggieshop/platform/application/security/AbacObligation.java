package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;
import java.util.Map;

/**
 * Obligation returned with a {@code CHALLENGE} effect.
 *
 * @param type the obligation type to be enforced (non-null)
 * @param params optional parameters for the obligation; defensively copied and never {@code null}
 */
public record AbacObligation(@NotNull Type type, Map<String, String> params) {

  /** Canonical constructor that normalizes {@code params} to an immutable, non-null map. */
  public AbacObligation {
    params = (params == null) ? Map.of() : Map.copyOf(params);
  }

  /** Supported obligation types returned alongside a challenge decision. */
  public enum Type {
    REQUIRE_MFA,
    REQUIRE_TWO_PERSON,
    REQUIRE_ELEVATION
  }

  /**
   * Creates an obligation requiring multi-factor authentication.
   *
   * @param strength strength label (e.g., {@code "strong"} or {@code "phishing-resistant"})
   * @return an MFA obligation
   */
  public static AbacObligation requireMfa(String strength) {
    return new AbacObligation(Type.REQUIRE_MFA, Map.of("strength", strength));
  }

  /**
   * Creates an obligation requiring two-person approval.
   *
   * @return a two-person approval obligation
   */
  public static AbacObligation requireTwoPerson() {
    return new AbacObligation(Type.REQUIRE_TWO_PERSON, Map.of());
  }

  /**
   * Creates an obligation requiring temporary privilege elevation.
   *
   * @param minutes minimum elevation duration in minutes
   * @return a privilege-elevation obligation
   */
  public static AbacObligation requireElevation(int minutes) {
    return new AbacObligation(
        Type.REQUIRE_ELEVATION, Map.of("minDurationMinutes", String.valueOf(minutes)));
  }
}
