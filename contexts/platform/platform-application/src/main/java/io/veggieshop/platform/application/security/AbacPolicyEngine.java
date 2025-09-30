package io.veggieshop.platform.application.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.micrometer.core.instrument.MeterRegistry;
import io.veggieshop.platform.application.security.AbacDefaults.Risk;
import io.veggieshop.platform.application.security.AbacRequest.Action;
import io.veggieshop.platform.application.security.AbacRequest.MfaLevel;
import io.veggieshop.platform.application.security.AbacRequest.Role;
import io.veggieshop.platform.domain.security.RiskLevel;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.validation.constraints.NotNull;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ABAC (Attribute-Based Access Control) policy engine.
 *
 * <p>Depends on top-level types: {@link AbacRequest}, {@link AbacDecision}, {@link AbacResource},
 * {@link AbacObligation}, {@link AbacDefaults}.
 */
public class AbacPolicyEngine {

  private static final Logger log = LoggerFactory.getLogger(AbacPolicyEngine.class);

  private final MeterRegistry metrics;
  private final Clock clock;
  private final AbacDefaults defaults;

  /**
   * Creates an engine with {@link AbacDefaults#strict()} defaults.
   *
   * @param metrics Micrometer registry (dependency is stored as-is; not exposed)
   * @param clock time source
   */
  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP2",
      justification =
          "Dependencies are injected and stored by reference; "
              + "the class neither mutates nor exposes them.")
  public AbacPolicyEngine(MeterRegistry metrics, Clock clock) {
    this(metrics, clock, AbacDefaults.strict());
  }

  /**
   * Creates an engine with custom defaults.
   *
   * @param metrics Micrometer registry (dependency is stored as-is; not exposed)
   * @param clock time source
   * @param defaults policy defaults (record; internally copies its map)
   */
  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP2",
      justification =
          "Dependencies are injected and stored by reference; "
              + "the class neither mutates nor exposes them.")
  public AbacPolicyEngine(MeterRegistry metrics, Clock clock, AbacDefaults defaults) {
    this.metrics = metrics;
    this.clock = clock;
    this.defaults = defaults;
  }

  /**
   * Main authorization evaluation entry point.
   *
   * @param req authorization request with subject, action, resource and environment
   * @return decision to PERMIT, DENY, or CHALLENGE (with obligations)
   */
  public AbacDecision authorize(@NotNull AbacRequest req) {
    final Instant now = clock.instant();

    // (0) Tenant isolation
    if (isBlank(req.tenantId()) || isBlank(req.subject().tenantId())) {
      return deny("Missing tenant context");
    }
    if (!req.tenantId().equals(req.subject().tenantId())) {
      return deny("Tenant mismatch");
    }
    if (req.resource() != null && !req.tenantId().equals(req.resource().tenantId())) {
      return deny("Resource not in caller tenant");
    }

    // (1) Basic RBAC screen
    if (!isRolePermittedForAction(req.subject().roles(), req.action())) {
      return deny("RBAC does not permit action " + req.action());
    }

    // (2) Vendor ownership (non-ADMIN only)
    if (!req.subject().roles().contains(Role.ADMIN)
        && req.resource() != null
        && req.resource().vendorOwnerId().isPresent()) {
      String owner = req.resource().vendorOwnerId().get();
      String callerVendor = req.subject().vendorId().orElse("<none>");
      if (!owner.equals(callerVendor)) {
        return deny("Vendor ownership required");
      }
    }

    // (3) Resource sensitivity gates
    AbacResource.Sensitivity sensitivity =
        Optional.ofNullable(req.resource())
            .map(AbacResource::sensitivity)
            .orElse(AbacResource.Sensitivity.INTERNAL);

    if (sensitivity == AbacResource.Sensitivity.RESTRICTED_PII) {
      if (!req.subject().roles().contains(Role.ADMIN)) {
        return deny("Restricted PII requires ADMIN role");
      }
      if (!hasStrongMfa(req.subject(), now)) {
        return challenge(
            AbacObligation.requireMfa("strong"), "Strong MFA required for restricted PII");
      }
    }

    if (sensitivity == AbacResource.Sensitivity.CONFIDENTIAL && isWrite(req.action())) {
      if (!req.subject().roles().contains(Role.ADMIN)) {
        return deny("Confidential writes require ADMIN");
      }
      if (!hasStrongMfa(req.subject(), now)) {
        return challenge(
            AbacObligation.requireMfa("strong"), "Strong MFA required for confidential writes");
      }
    }

    // (4) Action risk gates
    Risk risk = defaults.riskOf(req.action());
    if (risk != Risk.LOW) {
      if (!req.environment().breakGlass() && !hasStrongMfa(req.subject(), now)) {
        return challenge(
            AbacObligation.requireMfa("strong"), "Step-up MFA required for " + risk + " risk");
      }
    }

    if (risk == Risk.HIGH) {
      if (!req.subject().roles().contains(Role.ADMIN)) {
        return deny("High-risk action requires ADMIN");
      }
      if (!req.environment().breakGlass()) {
        if (req.environment().secondApprover().isEmpty()) {
          return challenge(AbacObligation.requireTwoPerson(), "Second approver required");
        }
        if (req.environment().secondApprover().get().equals(req.subject().userId())) {
          return deny("Second approver must differ from requester");
        }
      }
    }

    // (5) Environment risk → MFA
    if (req.environment().riskScore() >= defaults.environmentRiskMfaThreshold()
        && !req.environment().breakGlass()
        && !hasStrongMfa(req.subject(), now)) {
      return challenge(
          AbacObligation.requireMfa("strong"), "Environment risk requires step-up MFA");
    }

    // (6) Just-in-time elevation for specific actions
    if (requiresElevation(req.action())) {
      if (!hasValidElevation(req.subject(), now)) {
        return challenge(
            AbacObligation.requireElevation(defaults.minElevationMinutes()),
            "Just-in-time elevation required");
      }
    }

    // (7) SUPPORT is read-only
    if (req.subject().roles().contains(Role.SUPPORT) && isWrite(req.action())) {
      return deny("Support role is read-only");
    }

    metrics
        .counter("abac.permit", "action", req.action().name(), "sensitivity", sensitivity.name())
        .increment();
    return AbacDecision.permit("Permit by ABAC policy");
  }

  // ===== Internals ==========================================================

  private boolean isRolePermittedForAction(Set<Role> roles, Action action) {
    if (roles.contains(Role.ADMIN)) {
      return true;
    }
    return switch (action) {
      case READ ->
          roles.stream().anyMatch(r -> r == Role.BUYER || r == Role.VENDOR || r == Role.SUPPORT);
      case CREATE, UPDATE -> roles.contains(Role.VENDOR);
      case DELETE -> false; // high-privilege
      case APPROVE_PRICE_OVERRIDE, MANAGE_SECRETS, EXPORT_PII, MANAGE_TENANT_CONFIG -> false;
    };
  }

  private static boolean isWrite(Action action) {
    return action == Action.CREATE
        || action == Action.UPDATE
        || action == Action.DELETE
        || action == Action.APPROVE_PRICE_OVERRIDE
        || action == Action.MANAGE_SECRETS
        || action == Action.EXPORT_PII
        || action == Action.MANAGE_TENANT_CONFIG;
  }

  private static boolean requiresElevation(Action action) {
    return action == Action.MANAGE_SECRETS
        || action == Action.MANAGE_TENANT_CONFIG
        || action == Action.APPROVE_PRICE_OVERRIDE;
  }

  private static boolean hasStrongMfa(AbacRequest.Subject s, Instant now) {
    return s.mfaLevel() == MfaLevel.STRONG
        || (s.elevationUntil().isPresent() && s.elevationUntil().get().isAfter(now));
  }

  private static boolean hasValidElevation(AbacRequest.Subject s, Instant now) {
    return s.elevationUntil().isPresent() && s.elevationUntil().get().isAfter(now);
  }

  private AbacDecision deny(String reason) {
    metrics.counter("abac.deny").increment();
    log.debug("ABAC DENY: {}", reason);
    return AbacDecision.deny(reason);
  }

  private AbacDecision challenge(AbacObligation obligation, String reason) {
    metrics.counter("abac.challenge", "obligation", obligation.type().name()).increment();
    log.debug("ABAC CHALLENGE: {} (obligation={})", reason, obligation);
    return AbacDecision.challenge(reason, Set.of(obligation));
  }

  private static boolean isBlank(String s) {
    return s == null || s.isBlank();
  }

  // ===== Adapter helper for "throw if not permitted" ========================

  /**
   * Convenience method that throws if the action is not permitted.
   *
   * <p>Builds a minimal {@code system} subject. Infra layers may build a richer {@link AbacRequest}
   * from HTTP context instead.
   *
   * @param tenantId tenant identifier
   * @param resourceType logical resource type (used to infer sensitivity)
   * @param actionName action name (falls back to READ if unrecognized)
   * @param riskLevel not currently used for policy, but kept for API symmetry
   * @throws SecurityException if decision is DENY or CHALLENGE
   */
  public void require(
      TenantId tenantId, String resourceType, String actionName, RiskLevel riskLevel) {
    AbacRequest.Subject subject =
        new AbacRequest.Subject(
            "<system>",
            tenantId.value(),
            Set.of(Role.ADMIN),
            Optional.empty(),
            MfaLevel.STRONG,
            Optional.empty());

    AbacResource.Sensitivity sensitivity =
        (resourceType != null && resourceType.toUpperCase().contains("PII"))
            ? AbacResource.Sensitivity.RESTRICTED_PII
            : AbacResource.Sensitivity.INTERNAL;

    AbacResource resource =
        new AbacResource(tenantId.value(), Optional.empty(), sensitivity, resourceType);

    AbacRequest.Environment env = new AbacRequest.Environment(0, false, Optional.empty());
    Action action = mapActionName(actionName);

    AbacDecision d = authorize(new AbacRequest(tenantId.value(), subject, action, resource, env));
    switch (d.effect()) {
      case DENY -> throw new SecurityException("ABAC deny: " + d.reason());
      case CHALLENGE -> throw new SecurityException("ABAC challenge: " + d.reason());
      case PERMIT -> {
        /* ok */
      }
      default -> {
        /* enum exhaustive; default for Checkstyle */
      }
    }
  }

  private static Action mapActionName(String name) {
    try {
      return Action.valueOf(name);
    } catch (Exception ignored) {
      return Action.READ;
    }
  }
}
