package io.veggieshop.platform.infrastructure.persistence.outbox;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UuidGenerator;
import org.hibernate.type.SqlTypes;

/**
 * Transactional Outbox record (PostgreSQL) to guarantee reliable event publishing.
 *
 * <p>Inserted in the same DB transaction as the domain state change; a reliable publisher drains
 * pending rows with {@code SELECT ... FOR UPDATE SKIP LOCKED} and publishes to Kafka.
 *
 * <p>PRD alignment:
 *
 * <ul>
 *   <li>Exactly-once (producer side): transactional outbox, reliable drain, KPIs (PRD §11)
 *   <li>Multi-tenancy: tenant scoped rows and topic selection (PRD §4)
 *   <li>No PII in payloads for search/capture contexts (PRD §8, §15) — store references only
 * </ul>
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>JSON payload/headers use Hibernate 6 JSON support; PostgreSQL column type should be JSONB.
 *   <li>Drainer should page by (status=PENDING AND available_at<=now) ORDER BY created_at ASC.
 *   <li>Backoff is controlled via available_at + attempts + last_error.
 * </ul>
 */
@Entity
@Table(
    name = "outbox",
    indexes = {
      @Index(name = "idx_outbox_pending", columnList = "status,available_at,created_at"),
      @Index(name = "idx_outbox_tenant_topic", columnList = "tenant_id,topic"),
      @Index(name = "idx_outbox_published_at", columnList = "published_at")
    })
public class OutboxEntity {

  private static final int ERR_MAX = 2048;

  @Id
  @GeneratedValue
  @UuidGenerator
  @Column(name = "id", nullable = false, updatable = false)
  private UUID id;

  /** Required tenant scope for isolation. */
  @Column(name = "tenant_id", nullable = false, length = 64, updatable = false)
  private String tenantId;

  /** Logical destination (e.g., Kafka topic). */
  @Column(name = "topic", nullable = false, length = 200, updatable = false)
  private String topic;

  /** Partitioning key for Kafka; optional. */
  @Column(name = "event_key", length = 512, updatable = false)
  private String eventKey;

  /** Optional aggregate type/id for diagnostics and ordering guarantees. */
  @Column(name = "aggregate_type", length = 120, updatable = false)
  private String aggregateType;

  @Column(name = "aggregate_id", length = 120, updatable = false)
  private String aggregateId;

  /** Optional domain event type name (contract family). */
  @Column(name = "event_type", length = 160, updatable = false)
  private String eventType;

  /** Entity version at time of write (useful for X-Entity-Version header). */
  @Column(name = "entity_version", updatable = false)
  private Long entityVersion;

  /** Event payload (contracted JSON). Never include PII here. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "payload", nullable = false, columnDefinition = "jsonb")
  private JsonNode payload;

  /** Optional headers/extensions (e.g., schema fingerprint, trace id). */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "headers", columnDefinition = "jsonb")
  private JsonNode headers;

  /** Creation time (insert time in the DB transaction that produced the outbox record). */
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  /**
   * Availability time for draining (supports scheduled/delayed publishing). Defaults to created_at;
   * drainer only picks rows with available_at <= now.
   */
  @Column(name = "available_at", nullable = false)
  private Instant availableAt;

  /** Publication timestamp (null until published successfully). */
  @Column(name = "published_at")
  private Instant publishedAt;

  /** Current state of the record. */
  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 24)
  private Status status;

  /** Number of publish attempts made by the drainer. */
  @Column(name = "attempts", nullable = false)
  private int attempts;

  /** Truncated last error message (publisher/drainer diagnostics). */
  @Column(name = "last_error", length = ERR_MAX)
  private String lastError;

  /** Optimistic version to avoid concurrent state transitions in the same row. */
  @Version
  @Column(name = "row_version", nullable = false)
  private long rowVersion;

  // -------------------------------------------------------------------------------------
  // Factory & lifecycle helpers
  // -------------------------------------------------------------------------------------

  protected OutboxEntity() {
    // for JPA
  }

  /**
   * Internal constructor with trusted, pre-validated arguments.
   *
   * <p>Must not throw to satisfy CT_CONSTRUCTOR_THROW.
   */
  private OutboxEntity(
      String tenantId,
      String topic,
      String eventKey,
      String aggregateType,
      String aggregateId,
      String eventType,
      Long entityVersion,
      JsonNode payload,
      JsonNode headers,
      Instant availableAt) {

    // No validation here; everything must be pre-validated in factory methods.
    this.tenantId = tenantId;
    this.topic = topic;
    this.eventKey = eventKey;
    this.aggregateType = aggregateType;
    this.aggregateId = aggregateId;
    this.eventType = eventType;
    this.entityVersion = entityVersion;
    this.payload = payload;
    this.headers = headers;

    this.status = Status.PENDING;
    this.attempts = 0;
    this.availableAt = availableAt;
  }

  /** Create a pending outbox record ready for publishing (available immediately). */
  public static OutboxEntity pendingNow(
      String tenantId,
      String topic,
      String eventKey,
      String aggregateType,
      String aggregateId,
      String eventType,
      Long entityVersion,
      JsonNode payload,
      JsonNode headers,
      Instant now) {

    // Validate & normalize BEFORE construction
    String t = requireNonBlank(tenantId, "tenantId");
    String tp = requireNonBlank(topic, "topic");
    JsonNode pl = Objects.requireNonNull(payload, "payload");
    Instant avail = (now != null) ? now : Instant.now();

    return new OutboxEntity(
        t,
        tp,
        nullIfBlank(eventKey),
        nullIfBlank(aggregateType),
        nullIfBlank(aggregateId),
        nullIfBlank(eventType),
        entityVersion,
        pl,
        headers,
        avail);
  }

  /** Create a scheduled outbox record (delayed publishing until availableAt). */
  public static OutboxEntity scheduled(
      String tenantId,
      String topic,
      String eventKey,
      String aggregateType,
      String aggregateId,
      String eventType,
      Long entityVersion,
      JsonNode payload,
      JsonNode headers,
      Instant now,
      Instant availableAt) {

    String t = requireNonBlank(tenantId, "tenantId");
    String tp = requireNonBlank(topic, "topic");
    JsonNode pl = Objects.requireNonNull(payload, "payload");
    Instant avail =
        Objects.requireNonNull(
            availableAt != null ? availableAt : now != null ? now : Instant.now(), "availableAt");

    return new OutboxEntity(
        t,
        tp,
        nullIfBlank(eventKey),
        nullIfBlank(aggregateType),
        nullIfBlank(aggregateId),
        nullIfBlank(eventType),
        entityVersion,
        pl,
        headers,
        avail);
  }

  /** Mark the record as successfully published. */
  public void markPublished(Instant when) {
    this.status = Status.PUBLISHED;
    this.publishedAt = Objects.requireNonNull(when, "when");
    this.lastError = null;
  }

  /**
   * Mark a publish failure and schedule the next attempt by updating availableAt. The drainer
   * should compute a backoff (e.g., exponential + jitter) and pass it here.
   */
  public void markFailed(String error, Instant nextAttemptAt) {
    this.status = Status.PENDING; // still pending, but delayed for retry
    this.attempts += 1;
    this.availableAt = Objects.requireNonNull(nextAttemptAt, "nextAttemptAt");
    this.lastError = truncate(error, ERR_MAX);
  }

  /** Quarantine the record (manual operator action required). */
  public void quarantine(String reason) {
    this.status = Status.QUARANTINED;
    this.lastError = truncate(reason, ERR_MAX);
  }

  // -------------------------------------------------------------------------------------
  // Getters (no setters; mutate via helpers above)
  // -------------------------------------------------------------------------------------

  public UUID getId() {
    return id;
  }

  public String getTenantId() {
    return tenantId;
  }

  public String getTopic() {
    return topic;
  }

  public String getEventKey() {
    return eventKey;
  }

  public String getAggregateType() {
    return aggregateType;
  }

  public String getAggregateId() {
    return aggregateId;
  }

  public String getEventType() {
    return eventType;
  }

  public Long getEntityVersion() {
    return entityVersion;
  }

  public JsonNode getPayload() {
    return payload;
  }

  public JsonNode getHeaders() {
    return headers;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getAvailableAt() {
    return availableAt;
  }

  public Instant getPublishedAt() {
    return publishedAt;
  }

  public Status getStatus() {
    return status;
  }

  public int getAttempts() {
    return attempts;
  }

  public String getLastError() {
    return lastError;
  }

  public long getRowVersion() {
    return rowVersion;
  }

  // -------------------------------------------------------------------------------------
  // Object contract
  // -------------------------------------------------------------------------------------

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof OutboxEntity that)) {
      return false;
    }
    return Objects.equals(id, that.id);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id);
  }

  @Override
  public String toString() {
    // Intentionally PII-safe: no payload content
    return "OutboxEntity{"
        + "id="
        + id
        + ", tenantId='"
        + tenantId
        + '\''
        + ", topic='"
        + topic
        + '\''
        + ", eventKey='"
        + eventKey
        + '\''
        + ", aggregateType='"
        + aggregateType
        + '\''
        + ", aggregateId='"
        + aggregateId
        + '\''
        + ", eventType='"
        + eventType
        + '\''
        + ", entityVersion="
        + entityVersion
        + ", status="
        + status
        + ", attempts="
        + attempts
        + ", createdAt="
        + createdAt
        + ", availableAt="
        + availableAt
        + ", publishedAt="
        + publishedAt
        + '}';
  }

  // -------------------------------------------------------------------------------------
  // Enums & utils
  // -------------------------------------------------------------------------------------

  /** Lifecycle states for transactional outbox processing. */
  public enum Status {
    /** Ready (or scheduled) to be drained/published. */
    PENDING,
    /** Successfully published to the destination (immutable thereafter). */
    PUBLISHED,
    /** Escalated to operator attention; drainer skips this row. */
    QUARANTINED
  }

  private static String truncate(String s, int max) {
    if (s == null) {
      return null;
    }
    if (s.length() <= max) {
      return s;
    }
    return s.substring(0, max);
  }

  private static String requireNonBlank(String s, String field) {
    if (s == null || s.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
    return s;
  }

  private static String nullIfBlank(String s) {
    return (s == null || s.isBlank()) ? null : s;
  }
}
