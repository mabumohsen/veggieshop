package io.veggieshop.platform.infrastructure.persistence.outbox;

import jakarta.persistence.QueryHint;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * OutboxRepository
 *
 * Transactional Outbox repository with Postgres-specific draining primitives:
 * - "FOR UPDATE SKIP LOCKED" native queries to safely parallelize publishers
 * - Lightweight update methods for publish/fail/quarantine without reloading entities
 *
 * PRD alignment:
 * - Exactly-once (producer side): transactional outbox + reliable drain + KPIs (PRD §11)
 * - Multi-tenant isolation (tenant-scoped selectors available) (PRD §4)
 * - Performance-friendly patterns: SKIP LOCKED + paging by created_at (PRD §16)
 *
 * Usage notes:
 * - Call lockNextBatch[...] inside a REQUIRED transaction; keep the transaction open
 *   while publishing so that row locks are held until you mark success/failure.
 * - Keep batch sizes small (e.g., 50–500) and respect datasource/statement timeouts
 *   configured in DataSourceTimeoutConfig.
 */
@Repository
public interface OutboxRepository extends JpaRepository<OutboxEntity, UUID> {

    // =====================================================================================
    // Batch locking (drain)
    // =====================================================================================

    /**
     * Lock the next batch of PENDING rows across all tenants using
     * "FOR UPDATE SKIP LOCKED". Rows remain locked until the current
     * transaction commits/rolls back.
     *
     * Order by created_at ASC ensures first-in-first-out publishing.
     */
    @Query(
            value = """
            SELECT *
            FROM outbox
            WHERE status = 'PENDING'
              AND available_at <= now()
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT :limit
            """,
            nativeQuery = true
    )
    @QueryHints({
            // Respect a reasonable statement timeout (ms); overridden by connectionInitSql as well
            @QueryHint(name = "jakarta.persistence.query.timeout", value = "2000"),
            // Hibernate optimization for streaming/batching (safe here)
            @QueryHint(name = org.hibernate.jpa.HibernateHints.HINT_FETCH_SIZE, value = "200")
    })
    List<OutboxEntity> lockNextBatch(@Param("limit") int limit);

    /**
     * Tenant-scoped variant to favor locality and allow per-tenant drainers
     * (optional; use when the publisher is partitioned by tenant).
     */
    @Query(
            value = """
            SELECT *
            FROM outbox
            WHERE status = 'PENDING'
              AND tenant_id = :tenantId
              AND available_at <= now()
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT :limit
            """,
            nativeQuery = true
    )
    @QueryHints({
            @QueryHint(name = "jakarta.persistence.query.timeout", value = "2000"),
            @QueryHint(name = org.hibernate.jpa.HibernateHints.HINT_FETCH_SIZE, value = "200")
    })
    List<OutboxEntity> lockNextBatchForTenant(@Param("tenantId") String tenantId,
                                              @Param("limit") int limit);

    // =====================================================================================
    // State transitions (lean updates)
    // =====================================================================================

    /**
     * Mark a record as successfully published.
     * Returns the number of affected rows (0 if not found).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        UPDATE OutboxEntity o
           SET o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PUBLISHED,
               o.publishedAt = :when,
               o.lastError = NULL
         WHERE o.id = :id
        """)
    int markPublished(@Param("id") UUID id, @Param("when") Instant when);

    /**
     * Mark a publish failure, increment attempts, and delay next availability
     * for retry using backoff.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        UPDATE OutboxEntity o
           SET o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PENDING,
               o.attempts = o.attempts + 1,
               o.availableAt = :nextAttemptAt,
               o.lastError = :error
         WHERE o.id = :id
        """)
    int markFailed(@Param("id") UUID id,
                   @Param("error") String error,
                   @Param("nextAttemptAt") Instant nextAttemptAt);

    /**
     * Quarantine a problematic record (operator intervention required).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        UPDATE OutboxEntity o
           SET o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.QUARANTINED,
               o.lastError = :reason
         WHERE o.id = :id
        """)
    int quarantine(@Param("id") UUID id, @Param("reason") String reason);

    // =====================================================================================
    // Housekeeping
    // =====================================================================================

    /**
     * Delete old published rows to keep the table lean (housekeeping/TTL job).
     * Returns the number of deleted rows.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        DELETE FROM OutboxEntity o
         WHERE o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PUBLISHED
           AND o.publishedAt < :threshold
        """)
    int deletePublishedBefore(@Param("threshold") Instant threshold);

    /**
     * Lightweight counters for KPIs/telemetry.
     */
    long countByStatus(OutboxEntity.Status status);
    long countByStatusAndTenantId(OutboxEntity.Status status, String tenantId);

    /**
     * Convenience: how many rows are immediately drainable now.
     */
    @Query("""
        SELECT COUNT(o)
          FROM OutboxEntity o
         WHERE o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PENDING
           AND o.availableAt <= :now
        """)
    long countPendingAvailable(@Param("now") Instant now);

    @Query("""
        SELECT COUNT(o)
          FROM OutboxEntity o
         WHERE o.status = io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PENDING
           AND o.availableAt <= :now
           AND o.tenantId = :tenantId
        """)
    long countPendingAvailableForTenant(@Param("tenantId") String tenantId, @Param("now") Instant now);
}
