// AbacDefaults.java
package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotNull;

import java.util.EnumMap;
import java.util.Map;

/**
 * Default policy knobs. في الإنتاج اربطها بـ @ConfigurationProperties("security.abac") إذا لزم.
 */
public record AbacDefaults(
        int environmentRiskMfaThreshold, // riskScore >= threshold → require strong MFA
        @NotNull Map<AbacRequest.Action, Risk> actionRiskMap,
        int minElevationMinutes
) {
    public AbacDefaults {
        actionRiskMap = Map.copyOf(actionRiskMap);
    }

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

    public Risk riskOf(AbacRequest.Action action) {
        return actionRiskMap.getOrDefault(action, Risk.MEDIUM);
    }

    /** Risk classification for actions. */
    public enum Risk { LOW, MEDIUM, HIGH }
}
