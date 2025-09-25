// AbacRequest.java
package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/** ABAC request DTO (top-level). */
public record AbacRequest(
        @NotBlank String tenantId,
        @NotNull Subject subject,
        @NotNull Action action,
        AbacResource resource,                  // may be null for resource-less actions
        @NotNull Environment environment
) {

    /** Caller context (subject). */
    public record Subject(
            @NotBlank String userId,
            @NotBlank String tenantId,
            Set<Role> roles,
            Optional<String> vendorId,
            @NotNull MfaLevel mfaLevel,
            Optional<Instant> elevationUntil     // JIT elevation expiry (step-up window)
    ) {
        public Subject {
            roles = roles == null ? Set.of() : Set.copyOf(roles);
            vendorId = vendorId == null ? Optional.empty() : vendorId;
            elevationUntil = elevationUntil == null ? Optional.empty() : elevationUntil;
        }
    }

    /** Environment attributes for risk-aware decisions. */
    public record Environment(
            int riskScore,                     // 0..100 (aggregated risk: device/IP/geo anomalies)
            boolean breakGlass,                // emergency override (still audited)
            Optional<String> secondApprover    // userId of second approver when required
    ) {
        public Environment {
            secondApprover = secondApprover == null ? Optional.empty() : secondApprover;
            // clamp risk score to [0..100]
            riskScore = Math.max(0, Math.min(100, riskScore));
        }
    }

    /** Coarse RBAC roles. */
    public enum Role { BUYER, VENDOR, ADMIN, SUPPORT }

    /** MFA levels understood by the engine. */
    public enum MfaLevel { NONE, WEAK, STRONG }

    /** Supported actions; extend as needed per bounded context. */
    public enum Action {
        READ,
        CREATE,
        UPDATE,
        DELETE,
        APPROVE_PRICE_OVERRIDE,
        MANAGE_SECRETS,
        EXPORT_PII,
        MANAGE_TENANT_CONFIG
    }
}
