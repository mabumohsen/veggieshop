package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;
import java.util.EnumMap;
import java.util.Map;

/**
 * Default policy knobs.
 *
 * <p>In production, consider binding via {@code @ConfigurationProperties("security.abac")}.
 *
 * @param environmentRiskMfaThreshold environment risk score threshold at/above which strong MFA is
 *     required
 * @param actionRiskMap mapping from action to its baseline risk classification (non-null; copied
 *     defensively)
 * @param minElevationMinutes minimum duration (in minutes) for a privilege elevation
 */
public record AbacDefaults(
    int environmentRiskMfaThreshold, // riskScore >= threshold → require strong MFA
    @NotNull Map<AbacRequest.Action, Risk> actionRiskMap,
    int minElevationMinutes) {

  /** Canonical constructor that normalizes/copies the {@code actionRiskMap}. */
  public AbacDefaults {
    actionRiskMap = Map.copyOf(actionRiskMap);
  }

  /**
   * Returns a strict baseline configuration suitable for high-sensitivity environments.
   *
   * @return strict defaults with stronger requirements for mutating/privileged actions
   */
  public static AbacDefaults strict() {
    Map<AbacRequest.Action, Risk> map = new EnumMap<>(AbacRequest.Action.class);
    map.put(AbacRequest.Action.READ, Risk.LOW);
    map.put(AbacRequest.Action.CREATE, Risk.MEDIUM);
    map.put(AbacRequest.Action.UPDATE, Risk.MEDIUM);
    map.put(AbacRequest.Action.DELETE, Risk.HIGH);
    map.put(AbacRequest.Action.APPROVE_PRICE_OVERRIDE, Risk.HIGH);
    map.put(AbacRequest.Action.MANAGE_SECRETS, Risk.HIGH);
    map.put(AbacRequest.Action.EXPORT_PII, Risk.HIGH);
    map.put(AbacRequest.Action.MANAGE_TENANT_CONFIG, Risk.HIGH);
    return new AbacDefaults(60, Map.copyOf(map), 15);
  }

  /**
   * Returns the baseline risk classification for the given action.
   *
   * @param action the action being evaluated
   * @return the configured risk, or {@link Risk#MEDIUM} if not explicitly set
   */
  public Risk riskOf(AbacRequest.Action action) {
    return actionRiskMap.getOrDefault(action, Risk.MEDIUM);
  }

  /** Risk classification for actions. */
  public enum Risk {
    LOW,
    MEDIUM,
    HIGH
  }
}
