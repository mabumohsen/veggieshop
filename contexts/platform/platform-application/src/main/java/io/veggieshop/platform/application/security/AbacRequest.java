/*
 * VeggieShop Platform - ABAC types
 */

package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/**
 * ABAC request DTO (top-level).
 *
 * @param tenantId caller tenant identifier
 * @param subject caller context (user, roles, MFA, elevation)
 * @param action action being requested
 * @param resource target resource (may be {@code null} for resource-less actions)
 * @param environment environment attributes for risk-aware decisions
 */
public record AbacRequest(
    @NotBlank String tenantId,
    @NotNull Subject subject,
    @NotNull Action action,
    AbacResource resource, // may be null for resource-less actions
    @NotNull Environment environment) {

  /**
   * Caller context (subject).
   *
   * @param userId stable user identifier
   * @param tenantId tenant to which the subject belongs
   * @param roles coarse RBAC roles
   * @param vendorId optional vendor/owner id for multi-vendor scoping
   * @param mfaLevel current MFA assurance level
   * @param elevationUntil optional JIT elevation expiry (step-up window)
   */
  public record Subject(
      @NotBlank String userId,
      @NotBlank String tenantId,
      Set<Role> roles,
      Optional<String> vendorId,
      @NotNull MfaLevel mfaLevel,
      Optional<Instant> elevationUntil) {
    /** Canonicalizes nulls and copies collections to make the record safe. */
    public Subject {
      roles = (roles == null) ? Set.of() : Set.copyOf(roles);
      vendorId = (vendorId == null) ? Optional.empty() : vendorId;
      elevationUntil = (elevationUntil == null) ? Optional.empty() : elevationUntil;
    }
  }

  /**
   * Environment attributes for risk-aware decisions.
   *
   * @param riskScore aggregated environment risk (0..100; device/IP/geo anomalies)
   * @param breakGlass emergency override flag (still audited)
   * @param secondApprover optional userId of second approver when required
   */
  public record Environment(int riskScore, boolean breakGlass, Optional<String> secondApprover) {
    /** Canonicalizes nulls and clamps {@code riskScore} to the {@code [0,100]} range. */
    public Environment {
      secondApprover = (secondApprover == null) ? Optional.empty() : secondApprover;
      riskScore = Math.max(0, Math.min(100, riskScore));
    }
  }

  /** Coarse RBAC roles. */
  public enum Role {
    BUYER,
    VENDOR,
    ADMIN,
    SUPPORT
  }

  /** MFA levels understood by the engine. */
  public enum MfaLevel {
    NONE,
    WEAK,
    STRONG
  }

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
