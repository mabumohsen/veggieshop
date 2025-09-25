package io.veggieshop.platform.infrastructure.persistence.dedupe;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.Comment;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * EventDedupeEntity
 *
 * <p>Consumer-level de-duplication store for at-least-once Kafka consumption.
 * Aligns with PRD v2.0: dedupe key is (tenantId, eventId, eventVersion) and
 * entries are retained for at least the configured TTL (>= 7 days).
 *
 * <p>Design goals:
 * <ul>
 *   <li>Composite natural key to prevent duplicates without a surrogate ID.</li>
 *   <li>Indexes for expiry sweeps and operational introspection.</li>
 *   <li>No PII stored; optional trace/consumer metadata for observability.</li>
 *   <li>Pure JPA + Jakarta; DB-specific TTL jobs handled externally (Flyway/cron).</li>
 * </ul>
 */
@Entity
@Table(
        name = "event_dedupe",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_event_dedupe_tenant_event_version",
                        columnNames = {"tenant_id", "event_id", "event_version"}
                )
        },
        indexes = {
                @Index(name = "idx_event_dedupe_expires_at", columnList = "expires_at"),
                @Index(name = "idx_event_dedupe_processed_at", columnList = "processed_at"),
                @Index(name = "idx_event_dedupe_consumer", columnList = "consumer"),
                @Index(name = "idx_event_dedupe_family", columnList = "event_family")
        }
)
@Comment("Consumer de-duplication store (tenantId, eventId, version) → processed marker with TTL")
public class EventDedupeEntity implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Default retention as a safety net; concrete TTL should be supplied by the caller/config. */
    public static final Duration DEFAULT_TTL = Duration.ofDays(7);

    @EmbeddedId
    private EventDedupeKey key;

    @NotNull
    @Column(name = "processed_at", nullable = false, columnDefinition = "timestamptz")
    @Comment("When the event was first acknowledged/committed by the consumer")
    private Instant processedAt;

    @NotNull
    @Column(name = "expires_at", nullable = false, columnDefinition = "timestamptz")
    @Comment("Retention boundary; TTL sweeper deletes rows after this timestamp")
    private Instant expiresAt;

    @Size(max = 128)
    @Column(name = "consumer", length = 128)
    @Comment("Logical consumer id or group (for ops visibility); not part of the dedupe key")
    private String consumer;

    @Size(max = 64)
    @Column(name = "event_family", length = 64)
    @Comment("Optional event family/topic alias (ops segmentation)")
    private String eventFamily;

    @Size(max = 64)
    @Column(name = "trace_id", length = 64)
    @Comment("Optional trace correlation id for observability")
    private String traceId;

    @Size(max = 128)
    @Column(name = "payload_fingerprint", length = 128)
    @Comment("Optional payload fingerprint (e.g., sha256:...) for diagnostics; no payload stored")
    private String payloadFingerprint;

    /* ---------------------------- Constructors ---------------------------- */

    protected EventDedupeEntity() {
        // JPA
    }

    private EventDedupeEntity(
            EventDedupeKey key,
            Instant processedAt,
            Instant expiresAt,
            String consumer,
            String eventFamily,
            String traceId,
            String payloadFingerprint
    ) {
        this.key = Objects.requireNonNull(key, "key");
        this.processedAt = Objects.requireNonNull(processedAt, "processedAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.consumer = consumer;
        this.eventFamily = eventFamily;
        this.traceId = traceId;
        this.payloadFingerprint = payloadFingerprint;
    }

    /* ------------------------------ Factory ------------------------------ */

    /**
     * Create a dedupe marker with a specific TTL.
     */
    public static EventDedupeEntity create(
            @NotBlank String tenantId,
            @NotNull UUID eventId,
            long eventVersion,
            @NotNull Instant now,
            @NotNull Duration ttl,
            String consumer,
            String eventFamily,
            String traceId,
            String payloadFingerprint
    ) {
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("TTL must be positive");
        }
        var key = new EventDedupeKey(tenantId, eventId, eventVersion);
        return new EventDedupeEntity(
                key,
                now,
                now.plus(ttl),
                consumer,
                eventFamily,
                traceId,
                payloadFingerprint
        );
    }

    /**
     * Create a dedupe marker using the default TTL (>= 7 days).
     */
    public static EventDedupeEntity createWithDefaultTtl(
            @NotBlank String tenantId,
            @NotNull UUID eventId,
            long eventVersion,
            @NotNull Instant now,
            String consumer,
            String eventFamily,
            String traceId,
            String payloadFingerprint
    ) {
        return create(tenantId, eventId, eventVersion, now, DEFAULT_TTL, consumer, eventFamily, traceId, payloadFingerprint);
    }

    /* --------------------------- JPA Lifecycle --------------------------- */

    @PrePersist
    void prePersist() {
        // Defensive defaults if created via no-arg + setters
        var now = Instant.now();
        if (processedAt == null) {
            processedAt = now;
        }
        if (expiresAt == null) {
            expiresAt = processedAt.plus(DEFAULT_TTL);
        }
    }

    /* ------------------------------ Getters ------------------------------ */

    public EventDedupeKey getKey() {
        return key;
    }

    public Instant getProcessedAt() {
        return processedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getConsumer() {
        return consumer;
    }

    public String getEventFamily() {
        return eventFamily;
    }

    public String getTraceId() {
        return traceId;
    }

    public String getPayloadFingerprint() {
        return payloadFingerprint;
    }

    /* ------------------------------ Setters ------------------------------ */

    public void setKey(EventDedupeKey key) {
        this.key = key;
    }

    public void setProcessedAt(Instant processedAt) {
        this.processedAt = processedAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public void setConsumer(String consumer) {
        this.consumer = consumer;
    }

    public void setEventFamily(String eventFamily) {
        this.eventFamily = eventFamily;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public void setPayloadFingerprint(String payloadFingerprint) {
        this.payloadFingerprint = payloadFingerprint;
    }

    /* ------------------------------ Helpers ------------------------------ */

    public boolean isExpired(Instant referenceTime) {
        return expiresAt != null && referenceTime.isAfter(expiresAt);
    }

    @Override
    public String toString() {
        return "EventDedupeEntity{" +
                "tenantId=" + (key != null ? key.getTenantId() : "null") +
                ", eventId=" + (key != null ? key.getEventId() : "null") +
                ", version=" + (key != null ? key.getEventVersion() : "null") +
                ", processedAt=" + processedAt +
                ", expiresAt=" + expiresAt +
                ", consumer='" + consumer + '\'' +
                ", eventFamily='" + eventFamily + '\'' +
                ", traceId='" + traceId + '\'' +
                '}';
    }

    /* ============================== Key ================================= */

    @Embeddable
    @Comment("Composite natural key for dedupe (tenantId, eventId, eventVersion)")
    public static class EventDedupeKey implements Serializable {

        private static final long serialVersionUID = 1L;

        @NotBlank
        @Size(max = 64)
        @Column(name = "tenant_id", nullable = false, length = 64)
        private String tenantId;

        @NotNull
        @Column(name = "event_id", nullable = false, columnDefinition = "uuid")
        private UUID eventId;

        @Column(name = "event_version", nullable = false)
        private long eventVersion;

        protected EventDedupeKey() {
            // JPA
        }

        public EventDedupeKey(String tenantId, UUID eventId, long eventVersion) {
            this.tenantId = tenantId;
            this.eventId = eventId;
            this.eventVersion = eventVersion;
        }

        public String getTenantId() {
            return tenantId;
        }

        public UUID getEventId() {
            return eventId;
        }

        public long getEventVersion() {
            return eventVersion;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof EventDedupeKey that)) return false;
            return eventVersion == that.eventVersion
                    && Objects.equals(tenantId, that.tenantId)
                    && Objects.equals(eventId, that.eventId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(tenantId, eventId, eventVersion);
        }

        @Override
        public String toString() {
            return "EventDedupeKey{" +
                    "tenantId='" + tenantId + '\'' +
                    ", eventId=" + eventId +
                    ", eventVersion=" + eventVersion +
                    '}';
        }
    }
}
