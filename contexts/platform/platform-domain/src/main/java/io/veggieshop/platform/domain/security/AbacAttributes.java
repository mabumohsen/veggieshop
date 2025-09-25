package io.veggieshop.platform.domain.security;

import io.veggieshop.platform.domain.tenant.TenantId;

import java.time.Instant;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * AbacAttributes
 *
 * <p>Enterprise-grade, framework-agnostic attribute container for Attribute-Based Access Control (ABAC).
 * Lives in the <em>domain</em> module (no Spring/Servlet/Kafka deps) and is consumed by the
 * {@code AbacPolicyEngine} in the application layer.</p>
 *
 * <h2>Design goals (aligned with PRD v2.0)</h2>
 * <ul>
 *   <li><b>Multi-tenancy first:</b> attributes capture tenant alignment and vendor ownership to enforce “tenant match”.</li>
 *   <li><b>Defense-in-depth:</b> risk signals include data sensitivity (PII/PCI/PHI), action criticality, MFA state,
 *       just-in-time elevation, and two-person approval counts.</li>
 *   <li><b>Immutability:</b> instances are immutable and safely shareable across virtual threads.</li>
 *   <li><b>OPA-friendly:</b> {@link #toDecisionInput()} returns a primitive map for policy engines.</li>
 *   <li><b>No PII leakage:</b> fields are identifiers/booleans/categories only—no raw PII values.</li>
 * </ul>
 *
 * <h3>Typical usage</h3>
 * <pre>{@code
 * AbacAttributes attrs = AbacAttributes.builder(actorTenant, resourceTenant, "inventory.adjust")
 *     .actor(AbacAttributes.Actor.builder()
 *         .subjectId("user-123")
 *         .roles(EnumSet.of(Roles.ADMIN))
 *         .vendorId("vendor-77")
 *         .scopes(Set.of("inventory:write"))
 *         .authnStrength(AbacAttributes.AuthnStrength.MFA_STRONG)
 *         .stepUpMfaSatisfied(true)
 *         .justInTimeElevation(true)
 *         .build())
 *     .resource(AbacAttributes.Resource.builder()
 *         .resourceType("InventoryBatch")
 *         .resourceId("batch-abc")
 *         .ownerVendorId("vendor-77")
 *         .sensitivity(AbacAttributes.DataSensitivity.CONFIDENTIAL)
 *         .dataClasses(EnumSet.of(AbacAttributes.DataClass.PII))
 *         .build())
 *     .action(AbacAttributes.Action.builder()
 *         .name("inventory.adjust")
 *         .baseRisk(RiskLevel.HIGH)
 *         .requiresStepUpMfa(true)
 *         .requiresTwoPersonApproval(false)
 *         .build())
 *     .environment(AbacAttributes.Environment.builder()
 *         .requestTime(Instant.now())
 *         .ipAddress("203.0.113.10")
 *         .country("US")
 *         .clientId("bff-web")
 *         .traceId("abc123")
 *         .approvalsCount(1)
 *         .automated(false)
 *         .build())
 *     .build();
 *
 * // Example helpers:
 * boolean sameTenant = attrs.tenantsMatch();
 * RiskLevel effective = attrs.effectiveRiskLevel();
 * Map<String, Object> input = attrs.toDecisionInput(); // feed to policy engine / OPA
 * }</pre>
 */
public final class AbacAttributes {

    // ========= Core aggregate =========

    private final TenantId actorTenantId;
    private final TenantId resourceTenantId;
    private final String actionName;

    private final Actor actor;
    private final Resource resource;
    private final Action action;
    private final Environment environment;
    private final Map<String, Object> extensions; // extra, non-PII flags (reserved for future)

    private AbacAttributes(Builder b) {
        this.actorTenantId = Objects.requireNonNull(b.actorTenantId, "actorTenantId");
        this.resourceTenantId = Objects.requireNonNull(b.resourceTenantId, "resourceTenantId");
        this.actionName = requireNonBlank(b.actionName, "actionName");
        this.actor = Objects.requireNonNull(b.actor, "actor");
        this.resource = Objects.requireNonNull(b.resource, "resource");
        this.action = Objects.requireNonNull(b.action, "action");
        this.environment = Objects.requireNonNullElseGet(b.environment, () -> Environment.builder().build());
        this.extensions = Map.copyOf(Objects.requireNonNullElse(b.extensions, Map.of()));
    }

    // ========= Getters =========

    public TenantId actorTenantId() { return actorTenantId; }
    public TenantId resourceTenantId() { return resourceTenantId; }
    public String actionName() { return actionName; }
    public Actor actor() { return actor; }
    public Resource resource() { return resource; }
    public Action action() { return action; }
    public Environment environment() { return environment; }
    public Map<String, Object> extensions() { return extensions; }

    // ========= Convenience / signals =========

    /** Whether the actor’s tenant matches the resource’s tenant (primary guard). */
    public boolean tenantsMatch() {
        return actorTenantId.equals(resourceTenantId);
    }

    /** Whether vendor ownership is aligned when present on both sides. */
    public boolean vendorOwnershipAligned() {
        return actor.vendorId().isPresent()
                && resource.ownerVendorId().isPresent()
                && actor.vendorId().get().equals(resource.ownerVendorId().get());
    }

    /**
     * Compute an <em>effective</em> risk level combining action, data sensitivity, classes (PII/PCI/PHI),
     * and environmental modifiers. This is a heuristic to help the policy engine, not a hard rule.
     */
    public RiskLevel effectiveRiskLevel() {
        RiskLevel base = RiskLevel.max(
                action.baseRisk(),
                riskFor(resource.sensitivity()),
                riskFor(resource.dataClasses())
        );

        // Cross-tenant access elevates risk
        if (!tenantsMatch()) {
            base = elevate(base);
        }

        // Vendor mismatch on vendor-scoped resources elevates risk
        if (resource.ownerVendorId().isPresent()
                && actor.vendorId().isPresent()
                && !vendorOwnershipAligned()) {
            base = elevate(base);
        }

        // Step-up/MFA expectations
        if (action.requiresStepUpMfa() && !actor.stepUpMfaSatisfied()) {
            base = elevate(base); // missing step-up
        }

        // Two-person approval expectation
        if (action.requiresTwoPersonApproval() && environment.approvalsCount() < 2) {
            base = RiskLevel.CRITICAL; // force to highest if missing quorum
        }

        // Sensitive actions without JIT elevation get a bump
        if (base.ordinal() >= RiskLevel.HIGH.ordinal() && !actor.justInTimeElevation()) {
            base = elevate(base);
        }

        return base;
    }

    private static RiskLevel elevate(RiskLevel rl) {
        return switch (rl) {
            case LOW -> RiskLevel.MEDIUM;
            case MEDIUM -> RiskLevel.HIGH;
            case HIGH, CRITICAL -> RiskLevel.CRITICAL;
        };
    }

    private static RiskLevel riskFor(DataSensitivity s) {
        return switch (Objects.requireNonNullElse(s, DataSensitivity.INTERNAL)) {
            case PUBLIC -> RiskLevel.LOW;
            case INTERNAL -> RiskLevel.LOW;
            case CONFIDENTIAL -> RiskLevel.MEDIUM;
            case RESTRICTED -> RiskLevel.HIGH;
        };
    }

    private static RiskLevel riskFor(Set<DataClass> classes) {
        if (classes == null || classes.isEmpty()) return RiskLevel.LOW;
        if (classes.contains(DataClass.PCI)) return RiskLevel.CRITICAL;
        if (classes.contains(DataClass.PHI) || classes.contains(DataClass.PII)) return RiskLevel.HIGH;
        return RiskLevel.LOW;
    }

    /**
     * Produce a minimal, primitive map suitable for policy engines (e.g., OPA/Rego) and audit logs.
     * Contains no raw PII—only categories and identifiers.
     */
    public Map<String, Object> toDecisionInput() {
        return Map.of(
                "actorTenantId", actorTenantId.value(),
                "resourceTenantId", resourceTenantId.value(),
                "tenantsMatch", tenantsMatch(),
                "action", Map.of(
                        "name", actionName,
                        "baseRisk", action.baseRisk().name(),
                        "requiresStepUpMfa", action.requiresStepUpMfa(),
                        "requiresTwoPersonApproval", action.requiresTwoPersonApproval()
                ),
                "actor", Map.of(
                        "subjectId", actor.subjectId(),
                        "roles", actor.roles().stream().map(Enum::name).toList(),
                        "vendorId", actor.vendorId().orElse(null),
                        "scopes", actor.scopes(),
                        "authnStrength", actor.authnStrength().name(),
                        "stepUpMfaSatisfied", actor.stepUpMfaSatisfied(),
                        "justInTimeElevation", actor.justInTimeElevation()
                ),
                "resource", Map.of(
                        "type", resource.resourceType(),
                        "id", resource.resourceId(),
                        "ownerVendorId", resource.ownerVendorId().orElse(null),
                        "sensitivity", resource.sensitivity().name(),
                        "dataClasses", resource.dataClasses().stream().map(Enum::name).toList()
                ),
                "environment", Map.of(
                        "requestTime", Optional.ofNullable(environment.requestTime()).map(Instant::toString).orElse(null),
                        "ipAddress", environment.ipAddress(),
                        "country", environment.country(),
                        "clientId", environment.clientId(),
                        "traceId", environment.traceId(),
                        "approvalsCount", environment.approvalsCount(),
                        "automated", environment.automated()
                ),
                "effectiveRisk", effectiveRiskLevel().name(),
                "extensions", extensions
        );
    }

    // ========= Builder =========

    public static Builder builder(TenantId actorTenantId, TenantId resourceTenantId, String actionName) {
        return new Builder(actorTenantId, resourceTenantId, actionName);
    }

    public static final class Builder {
        private final TenantId actorTenantId;
        private final TenantId resourceTenantId;
        private final String actionName;

        private Actor actor = Actor.builder().build();
        private Resource resource = Resource.builder().build();
        private Action action = Action.builder().build();
        private Environment environment;
        private Map<String, Object> extensions;

        private Builder(TenantId actorTenantId, TenantId resourceTenantId, String actionName) {
            this.actorTenantId = Objects.requireNonNull(actorTenantId, "actorTenantId");
            this.resourceTenantId = Objects.requireNonNull(resourceTenantId, "resourceTenantId");
            this.actionName = requireNonBlank(actionName, "actionName");
        }

        public Builder actor(Actor actor) {
            this.actor = Objects.requireNonNull(actor, "actor");
            return this;
        }

        public Builder resource(Resource resource) {
            this.resource = Objects.requireNonNull(resource, "resource");
            return this;
        }

        public Builder action(Action action) {
            this.action = Objects.requireNonNull(action, "action");
            return this;
        }

        public Builder environment(Environment environment) {
            this.environment = environment;
            return this;
        }

        public Builder extensions(Map<String, Object> extensions) {
            this.extensions = extensions;
            return this;
        }

        public AbacAttributes build() {
            return new AbacAttributes(this);
        }
    }

    // ========= Nested value types =========

    /** Authentication strength used for policy hints (no secrets/PII). */
    public enum AuthnStrength {
        NONE, PASSWORD, MFA_WEAK, MFA_STRONG, HARDWARE_KEY
    }

    /** Data classification wrapper aligned with the PRD Data Catalog. */
    public enum DataClass {
        GENERIC, PII, PCI, PHI
    }

    /** High-level sensitivity of the resource. */
    public enum DataSensitivity {
        PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    }

    /**
     * Actor (subject) attributes.
     * Keep values coarse-grained—no PII. {@code vendorId} is a stable identifier, not a name.
     */
    public static final class Actor {
        private final String subjectId;
        private final Set<Roles> roles;
        private final String vendorId; // optional
        private final Set<String> scopes;
        private final AuthnStrength authnStrength;
        private final boolean stepUpMfaSatisfied;
        private final boolean justInTimeElevation;

        private Actor(Builder b) {
            this.subjectId = b.subjectId;
            this.roles = Collections.unmodifiableSet(Objects.requireNonNullElse(b.roles, EnumSet.noneOf(Roles.class)));
            this.vendorId = b.vendorId;
            this.scopes = Collections.unmodifiableSet(Objects.requireNonNullElse(b.scopes, Set.of()));
            this.authnStrength = Objects.requireNonNullElse(b.authnStrength, AuthnStrength.NONE);
            this.stepUpMfaSatisfied = b.stepUpMfaSatisfied;
            this.justInTimeElevation = b.justInTimeElevation;
        }

        public String subjectId() { return subjectId; }
        public Set<Roles> roles() { return roles; }
        public Optional<String> vendorId() { return Optional.ofNullable(vendorId); }
        public Set<String> scopes() { return scopes; }
        public AuthnStrength authnStrength() { return authnStrength; }
        public boolean stepUpMfaSatisfied() { return stepUpMfaSatisfied; }
        public boolean justInTimeElevation() { return justInTimeElevation; }

        public static Builder builder() { return new Builder(); }
        public static final class Builder {
            private String subjectId;
            private Set<Roles> roles;
            private String vendorId;
            private Set<String> scopes;
            private AuthnStrength authnStrength;
            private boolean stepUpMfaSatisfied;
            private boolean justInTimeElevation;

            public Builder subjectId(String subjectId) { this.subjectId = subjectId; return this; }
            public Builder roles(Set<Roles> roles) { this.roles = roles; return this; }
            public Builder vendorId(String vendorId) { this.vendorId = vendorId; return this; }
            public Builder scopes(Set<String> scopes) { this.scopes = scopes; return this; }
            public Builder authnStrength(AuthnStrength authnStrength) { this.authnStrength = authnStrength; return this; }
            public Builder stepUpMfaSatisfied(boolean v) { this.stepUpMfaSatisfied = v; return this; }
            public Builder justInTimeElevation(boolean v) { this.justInTimeElevation = v; return this; }
            public Actor build() { return new Actor(this); }
        }
    }

    /**
     * Resource attributes.
     * Only identifiers and categories—no descriptive PII payloads.
     */
    public static final class Resource {
        private final String resourceType;
        private final String resourceId;
        private final String ownerVendorId; // optional
        private final DataSensitivity sensitivity;
        private final Set<DataClass> dataClasses;

        private Resource(Builder b) {
            this.resourceType = Objects.requireNonNullElse(b.resourceType, "Unknown");
            this.resourceId = b.resourceId; // may be null for list-level checks
            this.ownerVendorId = b.ownerVendorId;
            this.sensitivity = Objects.requireNonNullElse(b.sensitivity, DataSensitivity.INTERNAL);
            this.dataClasses = Collections.unmodifiableSet(Objects.requireNonNullElse(b.dataClasses, EnumSet.noneOf(DataClass.class)));
        }

        public String resourceType() { return resourceType; }
        public String resourceId() { return resourceId; }
        public Optional<String> ownerVendorId() { return Optional.ofNullable(ownerVendorId); }
        public DataSensitivity sensitivity() { return sensitivity; }
        public Set<DataClass> dataClasses() { return dataClasses; }

        public static Builder builder() { return new Builder(); }
        public static final class Builder {
            private String resourceType;
            private String resourceId;
            private String ownerVendorId;
            private DataSensitivity sensitivity;
            private Set<DataClass> dataClasses;

            public Builder resourceType(String resourceType) { this.resourceType = resourceType; return this; }
            public Builder resourceId(String resourceId) { this.resourceId = resourceId; return this; }
            public Builder ownerVendorId(String ownerVendorId) { this.ownerVendorId = ownerVendorId; return this; }
            public Builder sensitivity(DataSensitivity sensitivity) { this.sensitivity = sensitivity; return this; }
            public Builder dataClasses(Set<DataClass> dataClasses) { this.dataClasses = dataClasses; return this; }
            public Resource build() { return new Resource(this); }
        }
    }

    /**
     * Action semantics for the attempted operation.
     * {@code name} follows a dotted convention: e.g., {@code "catalog.write"}, {@code "checkout.placeOrder"}.
     */
    public static final class Action {
        private final String name;
        private final RiskLevel baseRisk;
        private final boolean requiresStepUpMfa;
        private final boolean requiresTwoPersonApproval;

        private Action(Builder b) {
            this.name = requireNonBlank(Objects.requireNonNullElse(b.name, "unknown"), "name");
            this.baseRisk = Objects.requireNonNullElse(b.baseRisk, RiskLevel.LOW);
            this.requiresStepUpMfa = b.requiresStepUpMfa;
            this.requiresTwoPersonApproval = b.requiresTwoPersonApproval;
        }

        public String name() { return name; }
        public RiskLevel baseRisk() { return baseRisk; }
        public boolean requiresStepUpMfa() { return requiresStepUpMfa; }
        public boolean requiresTwoPersonApproval() { return requiresTwoPersonApproval; }

        public static Builder builder() { return new Builder(); }
        public static final class Builder {
            private String name;
            private RiskLevel baseRisk;
            private boolean requiresStepUpMfa;
            private boolean requiresTwoPersonApproval;

            public Builder name(String name) { this.name = name; return this; }
            public Builder baseRisk(RiskLevel baseRisk) { this.baseRisk = baseRisk; return this; }
            public Builder requiresStepUpMfa(boolean v) { this.requiresStepUpMfa = v; return this; }
            public Builder requiresTwoPersonApproval(boolean v) { this.requiresTwoPersonApproval = v; return this; }
            public Action build() { return new Action(this); }
        }
    }

    /**
     * Request environment (coarse metadata only).
     * Keep it safe for logs and policy evaluation.
     */
    public static final class Environment {
        private final Instant requestTime;
        private final String ipAddress;
        private final String country;
        private final String clientId;
        private final String traceId;
        private final int approvalsCount;
        private final boolean automated;

        private Environment(Builder b) {
            this.requestTime = b.requestTime;
            this.ipAddress = b.ipAddress;
            this.country = b.country;
            this.clientId = b.clientId;
            this.traceId = b.traceId;
            this.approvalsCount = Math.max(0, b.approvalsCount);
            this.automated = b.automated;
        }

        public Instant requestTime() { return requestTime; }
        public String ipAddress() { return ipAddress; }
        public String country() { return country; }
        public String clientId() { return clientId; }
        public String traceId() { return traceId; }
        public int approvalsCount() { return approvalsCount; }
        public boolean automated() { return automated; }

        public static Builder builder() { return new Builder(); }
        public static final class Builder {
            private Instant requestTime;
            private String ipAddress;
            private String country;
            private String clientId;
            private String traceId;
            private int approvalsCount;
            private boolean automated;

            public Builder requestTime(Instant requestTime) { this.requestTime = requestTime; return this; }
            public Builder ipAddress(String ipAddress) { this.ipAddress = ipAddress; return this; }
            public Builder country(String country) { this.country = country; return this; }
            public Builder clientId(String clientId) { this.clientId = clientId; return this; }
            public Builder traceId(String traceId) { this.traceId = traceId; return this; }
            public Builder approvalsCount(int approvalsCount) { this.approvalsCount = approvalsCount; return this; }
            public Builder automated(boolean automated) { this.automated = automated; return this; }
            public Environment build() { return new Environment(this); }
        }
    }

    // ========= Utils =========

    private static String requireNonBlank(String v, String name) {
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return v;
    }

    // ========= Static factory =========

    public static Builder builder(TenantId actorTenantId, TenantId resourceTenantId, CharSequence actionName) {
        return builder(actorTenantId, resourceTenantId, String.valueOf(actionName));
    }
}
