package io.veggieshop.platform.infrastructure.persistence.idempotency;

import jakarta.persistence.QueryHint;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * IdempotencyRepository
 *
 * Repository for idempotency records (HTTP mutating endpoints).
 *
 * PRD alignment:
 * - Every mutating endpoint requires Idempotency-Key; on replay, return the same response (PRD §10).
 * - Storage is monthly-partitioned by Flyway; entity maps to logical table "idempotency".
 * - Housekeeping deletes expired rows; queries keep strict tenant scoping (PRD §4, §16).
 *
 * Notes:
 * - For "create-if-absent" semantics, use {@link #insertIfAbsent(String, UUID, String, String, String, String, int, Instant)}.
 *   It performs a PostgreSQL upsert (ON CONFLICT DO NOTHING) and returns 1 if inserted, 0 if key already existed.
 * - Do NOT log response JSON (may contain sensitive data). Only log technical metadata (tenantId, key).
 */
@Repository
public interface IdempotencyRepository extends JpaRepository<IdempotencyEntity, IdempotencyEntity.Id> {

    // =====================================================================================
    // Lookups
    // =====================================================================================

    /**
     * Fetch a record by composite id (tenant-scoped key).
     */
    @Query("""
        SELECT e
          FROM IdempotencyEntity e
         WHERE e.id.tenantId = :tenantId
           AND e.id.key = :key
        """)
    @QueryHints(@QueryHint(name = "jakarta.persistence.query.timeout", value = "1500"))
    Optional<IdempotencyEntity> findOne(@Param("tenantId") String tenantId, @Param("key") UUID key);

    /**
     * Quick existence check to short-circuit request processing paths.
     */
    @Query("""
        SELECT COUNT(e) > 0
          FROM IdempotencyEntity e
         WHERE e.id.tenantId = :tenantId
           AND e.id.key = :key
        """)
    @QueryHints(@QueryHint(name = "jakarta.persistence.query.timeout", value = "1000"))
    boolean exists(@Param("tenantId") String tenantId, @Param("key") UUID key);

    // =====================================================================================
    // Create-if-absent (PostgreSQL upsert)
    // =====================================================================================

    /**
     * Insert a new idempotency record if absent. Returns 1 when inserted, 0 if it already exists.
     *
     * <p>Use this inside a REQUIRED transaction that also performs the business write.
     * The service layer should then either:
     *  - commit and return the response on first insert, or
     *  - read the existing row and return its stored response on duplicate (replay)
     *    with 2xx or 409 per API policy.</p>
     *
     * <p>Parameters:
     *  - responseJson: serialized JSON string (will be CAST to jsonb).
     *  - expiresAt: TTL enforced by housekeeping job.</p>
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            value = """
            INSERT INTO idempotency
                (tenant_id, key, request_hash, http_method, http_path, response_json, status_code, expires_at)
            VALUES
                (:tenantId, :key, :requestHash, :httpMethod, :httpPath, CAST(:responseJson AS jsonb), :statusCode, :expiresAt)
            ON CONFLICT (tenant_id, key) DO NOTHING
            """,
            nativeQuery = true
    )
    int insertIfAbsent(@Param("tenantId") String tenantId,
                       @Param("key") UUID key,
                       @Param("requestHash") String requestHash,
                       @Param("httpMethod") String httpMethod,
                       @Param("httpPath") String httpPath,
                       @Param("responseJson") String responseJson,
                       @Param("statusCode") int statusCode,
                       @Param("expiresAt") Instant expiresAt);

    // =====================================================================================
    // Housekeeping / KPIs
    // =====================================================================================

    /**
     * Delete expired rows (TTL). Returns the number of deleted rows.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        DELETE FROM IdempotencyEntity e
         WHERE e.expiresAt < :threshold
        """)
    int deleteExpiredBefore(@Param("threshold") Instant threshold);

    /**
     * Count per-tenant (useful for monitoring/alerts).
     */
    long countByIdTenantId(String tenantId);

    /**
     * Count rows expiring before a given time (pre-cleanup indicator).
     */
    @Query("""
        SELECT COUNT(e)
          FROM IdempotencyEntity e
         WHERE e.expiresAt < :threshold
        """)
    long countExpiringBefore(@Param("threshold") Instant threshold);
}
