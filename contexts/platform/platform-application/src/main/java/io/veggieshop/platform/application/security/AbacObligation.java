// AbacObligation.java
package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

/** Obligation returned with CHALLENGE effect. */
public record AbacObligation(
        @NotNull Type type,
        Map<String, String> params
) {
    public AbacObligation {
        params = params == null ? Map.of() : Map.copyOf(params);
    }

    public enum Type { REQUIRE_MFA, REQUIRE_TWO_PERSON, REQUIRE_ELEVATION }

    public static AbacObligation requireMfa(String strength) {
        return new AbacObligation(Type.REQUIRE_MFA, Map.of("strength", strength));
    }

    public static AbacObligation requireTwoPerson() {
        return new AbacObligation(Type.REQUIRE_TWO_PERSON, Map.of());
    }

    public static AbacObligation requireElevation(int minutes) {
        return new AbacObligation(Type.REQUIRE_ELEVATION, Map.of("minDurationMinutes", String.valueOf(minutes)));
    }
}
