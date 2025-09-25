package io.veggieshop.platform.domain.audit;

import io.veggieshop.platform.domain.version.EntityVersion;
import io.veggieshop.platform.domain.security.RiskLevel;
import io.veggieshop.platform.domain.security.Roles;
import io.veggieshop.platform.domain.tenant.TenantId;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public final class AuditMetadata {
    public static final String SCHEMA_ID = "veggieshop.audit.meta.v1";

    private final TenantId tenantId;
    private final String action;
    private final String resourceType;
    private final String resourceId;
    private final String actor;
    private final Instant occurredAt;

    private final EntityVersion entityVersion;
    private final EnumSet<Roles> roles;
    private final RiskLevel risk;
    private final String traceId;
    private final String correlationId;
    private final String client;
    private final String reason;

    private final AuditHash prevHash;
    private final AuditHash hash;
    private final SortedMap<String, String> attributes;

    private AuditMetadata(
            TenantId tenantId,
            String action,
            String resourceType,
            String resourceId,
            String actor,
            Instant occurredAt,
            EntityVersion entityVersion,
            EnumSet<Roles> roles,
            RiskLevel risk,
            String traceId,
            String correlationId,
            String client,
            String reason,
            AuditHash prevHash,
            AuditHash hash,
            SortedMap<String, String> attributes
    ) {
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
        this.action = requireCode(action, "action", 2, 80);
        this.resourceType = requireCode(resourceType, "resourceType", 2, 80);
        this.resourceId = requireToken(resourceId, "resourceId", 1, 120);
        this.actor = requireToken(actor, "actor", 1, 120);
        this.occurredAt = Objects.requireNonNullElse(occurredAt, Instant.now());

        this.entityVersion = entityVersion;
        this.roles = roles == null || roles.isEmpty() ? null : EnumSet.copyOf(roles);
        this.risk = Objects.requireNonNullElse(risk, RiskLevel.LOW);

        this.traceId = optionalToken(traceId, "traceId", 0, 64);
        this.correlationId = optionalToken(correlationId, "correlationId", 0, 64);
        this.client = optionalCode(client, "client", 0, 80);
        this.reason = optionalCode(reason, "reason", 0, 120);

        this.prevHash = prevHash;
        this.hash = hash;
        this.attributes = attributes == null ? Collections.emptySortedMap() : Collections.unmodifiableSortedMap(attributes);
    }

    // ---------------------------------------------------------------------
    // Builder
    // ---------------------------------------------------------------------

    public static Builder builder(TenantId tenantId, String action, String resourceType, String resourceId, String actor) {
        return new Builder(tenantId, action, resourceType, resourceId, actor);
    }

    public static final class Builder {
        private final TenantId tenantId;
        private final String action;
        private final String resourceType;
        private final String resourceId;
        private final String actor;

        private Instant occurredAt;
        private EntityVersion entityVersion;
        private EnumSet<Roles> roles;
        private RiskLevel risk = RiskLevel.LOW;
        private String traceId;
        private String correlationId;
        private String client;
        private String reason;
        private AuditHash prevHash;
        private SortedMap<String, String> attributes = new TreeMap<>();

        private Builder(TenantId tenantId, String action, String resourceType, String resourceId, String actor) {
            this.tenantId = Objects.requireNonNull(tenantId, "tenantId");
            this.action = action;
            this.resourceType = resourceType;
            this.resourceId = resourceId;
            this.actor = actor;
        }

        public Builder occurredAt(Instant occurredAt) { this.occurredAt = occurredAt; return this; }
        public Builder entityVersion(EntityVersion ev) { this.entityVersion = ev; return this; }
        public Builder roles(EnumSet<Roles> roles) { this.roles = roles; return this; }
        public Builder risk(RiskLevel risk) { this.risk = risk; return this; }
        public Builder traceId(String traceId) { this.traceId = traceId; return this; }
        public Builder correlationId(String correlationId) { this.correlationId = correlationId; return this; }
        public Builder client(String client) { this.client = client; return this; }
        public Builder reason(String reason) { this.reason = reason; return this; }
        public Builder prevHash(AuditHash prevHash) { this.prevHash = prevHash; return this; }

        public Builder attribute(String key, String value) {
            String k = requireAttrKey(key);
            String v = requireAttrValue(value);
            attributes.put(k, v);
            return this;
        }

        public AuditMetadata build() {
            return new AuditMetadata(
                    tenantId, action, resourceType, resourceId, actor, occurredAt,
                    entityVersion, roles, risk, traceId, correlationId, client, reason,
                    prevHash, null,
                    attributes
            );
        }

        public AuditMetadata buildAndComputeHash() {
            AuditMetadata tmp = build();
            AuditHash h = AuditHash.computeChained(tmp.prevHash, tmp.canonicalBytes());
            return tmp.withHash(h);
        }
    }

    // ---------------------------------------------------------------------
    // Domain operations
    // ---------------------------------------------------------------------

    public AuditMetadata withHash(AuditHash h) {
        return new AuditMetadata(
                tenantId, action, resourceType, resourceId, actor, occurredAt,
                entityVersion, roles, risk, traceId, correlationId, client, reason,
                prevHash, Objects.requireNonNull(h, "hash"), new TreeMap<>(attributes)
        );
    }

    public boolean verifyHash() {
        if (hash == null) return false;
        AuditHash computed = AuditHash.computeChained(prevHash, canonicalBytes());
        return hash.equals(computed);
    }

    public byte[] canonicalBytes() {
        StringBuilder sb = new StringBuilder(512);
        sb.append("schema:").append(SCHEMA_ID).append('\n');
        sb.append("tenant:").append(tenantId.value()).append('\n');
        sb.append("action:").append(action).append('\n');
        sb.append("resourceType:").append(resourceType).append('\n');
        sb.append("resourceId:").append(resourceId).append('\n');
        sb.append("actor:").append(actor).append('\n');

        sb.append("occurredAt:").append(occurredAt.toEpochMilli()).append('\n');
        sb.append("entityVersion:").append(entityVersion != null ? String.valueOf(entityVersion.value()) : "-").append('\n'); // replaced asString:contentReference[oaicite:0]{index=0}

        if (roles != null && !roles.isEmpty()) {
            List<String> names = new ArrayList<>(roles.size());
            for (Roles r : roles) names.add(r.name());
            Collections.sort(names);
            sb.append("roles:").append(String.join(",", names)).append('\n');
        } else {
            sb.append("roles:-\n");
        }

        sb.append("risk:").append(risk.name()).append('\n');
        sb.append("traceId:").append(blankToDash(traceId)).append('\n');

        sb.append("correlationId:").append(blankToDash(correlationId)).append('\n');
        sb.append("client:").append(blankToDash(client)).append('\n');
        sb.append("reason:").append(blankToDash(reason)).append('\n');

        if (!attributes.isEmpty()) {
            StringJoiner joiner = new StringJoiner(";");
            attributes.forEach((k, v) -> joiner.add(k + "=" + v));
            sb.append("attributes:").append(joiner).append('\n');
        } else {
            sb.append("attributes:-\n");
        }

        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    // ---------------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------------

    public TenantId tenantId() { return tenantId; }
    public String action() { return action; }
    public String resourceType() { return resourceType; }
    public String resourceId() { return resourceId; }
    public String actor() { return actor; }
    public Instant occurredAt() { return occurredAt; }
    public Optional<EntityVersion> entityVersion() { return Optional.ofNullable(entityVersion); }
    public Optional<EnumSet<Roles>> roles() { return Optional.ofNullable(roles == null ? null : EnumSet.copyOf(roles)); }
    public RiskLevel risk() { return risk; }
    public Optional<String> traceId() { return Optional.ofNullable(traceId); }
    public Optional<String> correlationId() { return Optional.ofNullable(correlationId); }
    public Optional<String> client() { return Optional.ofNullable(client); }
    public Optional<String> reason() { return Optional.ofNullable(reason); }
    public Optional<AuditHash> prevHash() { return Optional.ofNullable(prevHash); }
    public Optional<AuditHash> hash() { return Optional.ofNullable(hash); }
    public SortedMap<String, String> attributes() { return attributes; }

    // ---------------------------------------------------------------------
    // Object overrides (PII-safe)
    // ---------------------------------------------------------------------

    @Override
    public String toString() {
        return "AuditMetadata{" +
                "tenantId=" + tenantId.value() +
                ", action='" + action + '\'' +
                ", resourceType='" + resourceType + '\'' +
                ", resourceId='" + abbreviate(resourceId, 16) + '\'' +
                ", actor='" + abbreviate(actor, 16) + '\'' +
                ", occurredAt=" + occurredAt +
                ", entityVersion=" + (entityVersion != null ? entityVersion.value() : "-") + // replaced asString:contentReference[oaicite:1]{index=1}
                ", risk=" + risk +
                ", traceId=" + abbreviate(traceId, 16) +
                ", correlationId=" + abbreviate(correlationId, 16) +
                ", client=" + abbreviate(client, 16) +
                ", reason=" + abbreviate(reason, 32) +
                ", attributes=" + attributes.keySet() +
                ", prevHash=" + (prevHash != null ? prevHash.toString() : "-") +
                ", hash=" + (hash != null ? hash.toString() : "-") +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditMetadata that)) return false;
        return Objects.equals(tenantId, that.tenantId)
                && Objects.equals(action, that.action)
                && Objects.equals(resourceType, that.resourceType)
                && Objects.equals(resourceId, that.resourceId)
                && Objects.equals(actor, that.actor)
                && Objects.equals(occurredAt, that.occurredAt)
                && Objects.equals(entityVersion, that.entityVersion)
                && Objects.equals(roles, that.roles)
                && risk == that.risk
                && Objects.equals(traceId, that.traceId)
                && Objects.equals(correlationId, that.correlationId)
                && Objects.equals(client, that.client)
                && Objects.equals(reason, that.reason)
                && Objects.equals(prevHash, that.prevHash)
                && Objects.equals(hash, that.hash)
                && Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tenantId, action, resourceType, resourceId, actor, occurredAt,
                entityVersion, roles, risk, traceId, correlationId, client, reason, prevHash, hash, attributes);
    }

    // ---------------------------------------------------------------------
    // Validation helpers (ASCII, sizes, allowed chars)
    // ---------------------------------------------------------------------

    private static String requireCode(String value, String name, int min, int max) {
        String v = requireNonBlank(value, name);
        if (v.length() < min || v.length() > max) {
            throw new IllegalArgumentException(name + " length must be [" + min + "," + max + "]");
        }
        if (!v.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException(name + " must match [A-Za-z0-9._:-]+");
        }
        return v;
    }

    private static String optionalCode(String value, String name, int min, int max) {
        if (value == null || value.isBlank()) return null;
        return requireCode(value, name, Math.max(1, min), max);
    }

    private static String requireToken(String value, String name, int min, int max) {
        String v = requireNonBlank(value, name);
        if (v.length() < min || v.length() > max) {
            throw new IllegalArgumentException(name + " length must be [" + min + "," + max + "]");
        }
        if (!v.matches("[A-Za-z0-9._:@/\\-]+")) {
            throw new IllegalArgumentException(name + " contains illegal characters");
        }
        return v;
    }

    private static String optionalToken(String value, String name, int min, int max) {
        if (value == null || value.isBlank()) return null;
        return requireToken(value, name, Math.max(1, min), max);
    }

    private static String requireAttrKey(String key) {
        String k = requireNonBlank(key, "attribute key").toLowerCase(Locale.ROOT);
        if (k.length() > 40) throw new IllegalArgumentException("attribute key too long (max 40)");
        if (!k.matches("[a-z0-9\\-]+")) throw new IllegalArgumentException("attribute key must be lower-kebab-case");
        return k;
    }

    private static String requireAttrValue(String value) {
        String v = requireNonBlank(value, "attribute value");
        if (v.length() > 120) throw new IllegalArgumentException("attribute value too long (max 120)");
        for (int i = 0; i < v.length(); i++) {
            if (v.charAt(i) > 0x7F) throw new IllegalArgumentException("attribute value must be ASCII");
        }
        return v;
    }

    private static String requireNonBlank(String s, String name) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return s.trim();
    }

    private static String blankToDash(String s) {
        return (s == null || s.isBlank()) ? "-" : s;
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
