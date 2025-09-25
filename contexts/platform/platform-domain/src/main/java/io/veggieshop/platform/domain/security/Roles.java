package io.veggieshop.platform.domain.security;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Roles
 *
 * <p>Enterprise-grade role taxonomy for VeggieShop (BUYER, VENDOR, SUPPORT, ADMIN).
 * Framework-agnostic and safe for use in the domain layer. The enum provides:
 * </p>
 * <ul>
 *   <li><b>Stable, ordered roles</b> with a coarse trust score for policy hints.</li>
 *   <li><b>Hierarchy helpers</b> (e.g., {@link #isAtLeast(Roles)}, {@link #effectiveRoles()}).</li>
 *   <li><b>Authority mapping</b> without framework coupling (e.g., "ROLE_ADMIN").</li>
 *   <li><b>Lenient parsing/normalization</b> from claims/headers/user stores.</li>
 * </ul>
 *
 * <h2>Hierarchy (policy defaults)</h2>
 * <ul>
 *   <li><b>BUYER</b> → only BUYER.</li>
 *   <li><b>VENDOR</b> → VENDOR + BUYER (vendors also act as buyers in some paths).</li>
 *   <li><b>SUPPORT</b> → SUPPORT + BUYER (support staff do not inherit vendor privileges).</li>
 *   <li><b>ADMIN</b> → ADMIN + SUPPORT + VENDOR + BUYER.</li>
 * </ul>
 *
 * <p>NOTE: Fine-grained authorization must be handled by ABAC/policy engine. Role inheritance
 * here is a convenience for coarse gates and default UI enablement.</p>
 */
public enum Roles {
    BUYER(10, "Consumer/buyer persona"),
    VENDOR(40, "Vendor/merchant persona"),
    SUPPORT(60, "Support/CS persona"),
    ADMIN(90, "Tenant administrator");

    /** Coarse trust score (0..100) for dashboards and guardrails. */
    private final int trustScore;
    private final String description;

    Roles(int trustScore, String description) {
        this.trustScore = trustScore;
        this.description = description;
    }

    public int trustScore() {
        return trustScore;
    }

    public String description() {
        return description;
    }

    // -----------------------
    // Hierarchy & comparison
    // -----------------------

    /** @return true if this role is at least as privileged as {@code other}, by enum order. */
    public boolean isAtLeast(Roles other) {
        Objects.requireNonNull(other, "other");
        return this.ordinal() >= other.ordinal();
    }

    /**
     * Effective roles granted by this role according to VeggieShop defaults.
     * ADMIN → all; SUPPORT → SUPPORT + BUYER; VENDOR → VENDOR + BUYER; BUYER → BUYER.
     */
    public Set<Roles> effectiveRoles() {
        return switch (this) {
            case ADMIN -> EnumSet.allOf(Roles.class);
            case SUPPORT -> EnumSet.of(SUPPORT, BUYER);
            case VENDOR -> EnumSet.of(VENDOR, BUYER);
            case BUYER -> EnumSet.of(BUYER);
        };
    }

    /** Union of {@link #effectiveRoles()} across the provided set. */
    public static Set<Roles> expandEffective(Set<Roles> roles) {
        if (roles == null || roles.isEmpty()) return EnumSet.noneOf(Roles.class);
        EnumSet<Roles> out = EnumSet.noneOf(Roles.class);
        for (Roles r : roles) {
            if (r != null) out.addAll(r.effectiveRoles());
        }
        return out;
    }

    // -----------------------
    // Parsing & normalization
    // -----------------------

    /**
     * Lenient, case-insensitive parser from a single token.
     * Accepts canonical names (ADMIN), common aliases ("administrator", "support_agent"),
     * and authority style ("ROLE_ADMIN").
     */
    public static Optional<Roles> parse(String raw) {
        if (raw == null || raw.isBlank()) return Optional.empty();
        String s = raw.trim();
        // Strip common "ROLE_" prefix if present
        if (s.regionMatches(true, 0, DEFAULT_AUTHORITY_PREFIX, 0, DEFAULT_AUTHORITY_PREFIX.length())) {
            s = s.substring(DEFAULT_AUTHORITY_PREFIX.length());
        }
        String u = s.toUpperCase(Locale.ROOT);
        // Direct enum match
        for (Roles r : values()) {
            if (r.name().equals(u)) return Optional.of(r);
        }
        // Aliases
        return switch (u) {
            case "ADMINISTRATOR", "TENANT_ADMIN", "SYSADMIN", "SUPERADMIN" -> Optional.of(ADMIN);
            case "SUPPORT_AGENT", "CS", "CUSTOMER_SUPPORT" -> Optional.of(SUPPORT);
            case "MERCHANT", "SELLER" -> Optional.of(VENDOR);
            case "SHOPPER", "CUSTOMER", "CONSUMER" -> Optional.of(BUYER);
            default -> Optional.empty();
        };
    }

    /**
     * Parse a heterogeneous collection of role tokens (claims/headers/DB) into a set of {@link Roles}.
     * Unknown tokens are ignored.
     */
    public static Set<Roles> parseMany(Collection<String> tokens) {
        if (tokens == null || tokens.isEmpty()) return EnumSet.noneOf(Roles.class);
        EnumSet<Roles> out = EnumSet.noneOf(Roles.class);
        for (String t : tokens) {
            parse(t).ifPresent(out::add);
        }
        return out;
    }

    /** Highest role present, preferring ADMIN → SUPPORT → VENDOR → BUYER. */
    public static Optional<Roles> highestOf(Set<Roles> roles) {
        if (roles == null || roles.isEmpty()) return Optional.empty();
        Roles top = BUYER;
        for (Roles r : roles) {
            if (r != null && r.ordinal() > top.ordinal()) top = r;
        }
        return Optional.ofNullable(top);
    }

    // -----------------------
    // Authorities (framework-agnostic)
    // -----------------------

    /** Default authority prefix (kept minimal to avoid framework coupling). */
    public static final String DEFAULT_AUTHORITY_PREFIX = "ROLE_";

    /** Map this role to a simple authority string (e.g., "ROLE_ADMIN"). */
    public String toAuthority() {
        return toAuthority(DEFAULT_AUTHORITY_PREFIX);
    }

    /** Map this role to an authority string with a custom prefix. */
    public String toAuthority(String prefix) {
        String p = (prefix == null) ? "" : prefix;
        return p + name();
    }

    /** Convert a set of roles to authority strings using the default prefix. */
    public static Set<String> toAuthorities(Set<Roles> roles) {
        return toAuthorities(roles, DEFAULT_AUTHORITY_PREFIX);
    }

    /** Convert a set of roles to authority strings using a custom prefix. */
    public static Set<String> toAuthorities(Set<Roles> roles, String prefix) {
        if (roles == null || roles.isEmpty()) return Set.of();
        String p = (prefix == null) ? "" : prefix;
        return roles.stream().filter(Objects::nonNull).map(r -> p + r.name()).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** Inverse of {@link #toAuthority()}: parse a single authority (e.g., "ROLE_VENDOR"). */
    public static Optional<Roles> fromAuthority(String authority) {
        return parse(authority);
    }

    /** Inverse of {@link #toAuthorities(Set)} for a collection of authorities. */
    public static Set<Roles> fromAuthorities(Collection<String> authorities) {
        return parseMany(authorities);
    }
}
