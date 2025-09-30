package io.veggieshop.platform.infrastructure.persistence.idempotency;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * IdempotencyEntity
 *
 * <p>Transactional idempotency record for HTTP mutating endpoints. Stored in PostgreSQL
 * (partitioned monthly by migrations), keyed by (tenant_id, key).
 *
 * <p>PRD alignment:
 *
 * <ul>
 *   <li>Every mutating endpoint requires Idempotency-Key (PRD §10).
 *   <li>Store: (tenant_id, key, request_hash, response_json, status_code, created_at, expires_at).
 *   <li>TTL/Housekeeping jobs delete expired rows (PRD §10, §16).
 *   <li>No PII in logs; response_json must never be logged.
 * </ul>
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>Table is “idempotency”; monthly partitions managed by Flyway.
 *   <li>request_hash is a stable hash over method+path+canonicalized body(+headers).
 *   <li>On replay: if (tenant,key) exists and request_hash matches → return same response/status;
 *       else → 409 with retrieval pointer.
 * </ul>
 */
@Entity
@Table(
    name = "idempotency",
    indexes = {
      @Index(name = "idx_idem_tenant_created", columnList = "tenant_id,created_at"),
      @Index(name = "idx_idem_expires_at", columnList = "expires_at"),
      @Index(name = "idx_idem_tenant_reqhash", columnList = "tenant_id,request_hash"),
      @Index(name = "idx_idem_http", columnList = "http_method,http_path")
    })
public class IdempotencyEntity {

  // -------------------------------------------------------------------------------------
  // Composite key (tenant_id, key)
  // -------------------------------------------------------------------------------------

  /** Composite id for idempotency rows: (tenantId, key). */
  @Embeddable
  public static class Id {
    @Column(name = "tenant_id", nullable = false, length = 64, updatable = false)
    private String tenantId;

    @Column(name = "key", nullable = false, updatable = false)
    private UUID key;

    /** JPA constructor. */
    protected Id() {
      /* for JPA */
    }

    /** Plain constructor (no validation; factories validate beforehand). */
    public Id(String tenantId, UUID key) {
      this.tenantId = tenantId;
      this.key = key;
    }

    /**
     * Returns the tenant id scope.
     *
     * @return tenant id scope
     */
    public String getTenantId() {
      return tenantId;
    }

    /**
     * Returns the idempotency key.
     *
     * @return idempotency key (UUID)
     */
    public UUID getKey() {
      return key;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof Id that)) {
        return false;
      }
      return Objects.equals(tenantId, that.tenantId) && Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
      return Objects.hash(tenantId, key);
    }

    @Override
    public String toString() {
      return "Id{tenantId='" + tenantId + "', key=" + key + '}';
    }
  }

  @EmbeddedId private Id id;

  // -------------------------------------------------------------------------------------
  // Request fingerprint (hash over method + path + canonicalized body)
  // -------------------------------------------------------------------------------------

  /** Stable hash (e.g., hex-encoded SHA-256) of the canonical request. */
  @Column(name = "request_hash", nullable = false, length = 128, updatable = false)
  private String requestHash;

  /** HTTP method for diagnostics and optional uniqueness. */
  @Column(name = "http_method", nullable = false, length = 10, updatable = false)
  private String httpMethod;

  /** HTTP path template (without volatile query strings) for diagnostics. */
  @Column(name = "http_path", nullable = false, length = 512, updatable = false)
  private String httpPath;

  // -------------------------------------------------------------------------------------
  // Stored response snapshot (NEVER log contents; may hold user-sensitive data)
  // -------------------------------------------------------------------------------------

  /** JSONB response snapshot to be returned on idempotent replay. */
  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "response_json", nullable = false, columnDefinition = "jsonb")
  private JsonNode responseJson;

  /** HTTP status code of the original response. */
  @Column(name = "status_code", nullable = false)
  private int statusCode;

  // -------------------------------------------------------------------------------------
  // Timestamps & TTL
  // -------------------------------------------------------------------------------------

  /** Inserted at creation time (DB clock). */
  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  /** Expiration time after which this row is eligible for deletion. */
  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  /** Optional optimistic lock to avoid concurrent overwrites in rare edge cases. */
  @Version
  @Column(name = "row_version", nullable = false)
  private long rowVersion;

  // -------------------------------------------------------------------------------------
  // Constructors & factories
  // -------------------------------------------------------------------------------------

  /** JPA constructor. */
  protected IdempotencyEntity() {
    /* for JPA */
  }

  /**
   * Private constructor that assumes all arguments are pre-validated. (No validation here to avoid
   * SpotBugs CT_CONSTRUCTOR_THROW.)
   */
  private IdempotencyEntity(
      Id id,
      String requestHash,
      String httpMethod,
      String httpPath,
      JsonNode responseJson,
      int statusCode,
      Instant expiresAt) {
    this.id = id;
    this.requestHash = requestHash;
    this.httpMethod = httpMethod;
    this.httpPath = httpPath;
    this.responseJson = responseJson;
    this.statusCode = statusCode;
    this.expiresAt = expiresAt;
  }

  /** Factory: create a new idempotency record (validates inputs). */
  public static IdempotencyEntity of(
      String tenantId,
      UUID key,
      String requestHash,
      String httpMethod,
      String httpPath,
      JsonNode responseJson,
      int statusCode,
      Instant expiresAt) {

    // Validate first (outside constructor) → avoids CT_CONSTRUCTOR_THROW
    if (tenantId == null || tenantId.isBlank()) {
      throw new IllegalArgumentException("tenantId must not be blank");
    }
    if (key == null) {
      throw new IllegalArgumentException("key must not be null");
    }
    if (requestHash == null || requestHash.isBlank()) {
      throw new IllegalArgumentException("requestHash must not be blank");
    }
    if (httpMethod == null || httpMethod.isBlank()) {
      throw new IllegalArgumentException("httpMethod must not be blank");
    }
    if (httpPath == null || httpPath.isBlank()) {
      throw new IllegalArgumentException("httpPath must not be blank");
    }
    if (responseJson == null) {
      throw new IllegalArgumentException("responseJson must not be null");
    }
    if (expiresAt == null) {
      throw new IllegalArgumentException("expiresAt must not be null");
    }

    return new IdempotencyEntity(
        new Id(tenantId, key),
        requestHash,
        httpMethod,
        httpPath,
        responseJson,
        statusCode,
        expiresAt);
  }

  // -------------------------------------------------------------------------------------
  // Domain helpers
  // -------------------------------------------------------------------------------------

  /** Returns true when the record has expired and is eligible for cleanup. */
  public boolean isExpired(Instant now) {
    return now != null && expiresAt != null && now.isAfter(expiresAt);
  }

  // -------------------------------------------------------------------------------------
  // Getters (no public setters; entity is immutable after insert)
  // -------------------------------------------------------------------------------------

  public Id getId() {
    return id;
  }

  public String getTenantId() {
    return id != null ? id.getTenantId() : null;
  }

  public UUID getKey() {
    return id != null ? id.getKey() : null;
  }

  public String getRequestHash() {
    return requestHash;
  }

  public String getHttpMethod() {
    return httpMethod;
  }

  public String getHttpPath() {
    return httpPath;
  }

  public JsonNode getResponseJson() {
    return responseJson;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getExpiresAt() {
    return expiresAt;
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
    if (!(o instanceof IdempotencyEntity that)) {
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
    // PII-safe: never include responseJson contents
    return "IdempotencyEntity{"
        + "tenantId='"
        + getTenantId()
        + '\''
        + ", key="
        + getKey()
        + ", requestHash='"
        + requestHash
        + '\''
        + ", httpMethod='"
        + httpMethod
        + '\''
        + ", httpPath='"
        + httpPath
        + '\''
        + ", statusCode="
        + statusCode
        + ", createdAt="
        + createdAt
        + ", expiresAt="
        + expiresAt
        + '}';
  }
}
