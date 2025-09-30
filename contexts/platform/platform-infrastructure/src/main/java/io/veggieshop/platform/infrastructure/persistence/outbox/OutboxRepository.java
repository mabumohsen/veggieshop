package io.veggieshop.platform.infrastructure.persistence.outbox;

import jakarta.persistence.QueryHint;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Transactional Outbox repository with Postgres-specific draining primitives.
 *
 * <p>Patterns used:
 *
 * <ul>
 *   <li>{@code FOR UPDATE SKIP LOCKED} native queries to parallelize publishers safely.
 *   <li>Lean update queries for publish/fail/quarantine without reloading entities.
 *   <li>Housekeeping queries to prune published rows.
 * </ul>
 */
@Repository
public interface OutboxRepository extends JpaRepository<OutboxEntity, UUID> {

  // JPQL enum literals to avoid long inline strings
  String S_PUBLISHED =
      "io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PUBLISHED";
  String S_PENDING =
      "io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.PENDING";
  String S_QUARANTINED =
      "io.veggieshop.platform.infrastructure.persistence.outbox.OutboxEntity$Status.QUARANTINED";

  // =========================================================================
  // Batch locking (drain)
  // =========================================================================

  /** Lock next batch of PENDING rows (all tenants). */
  @Query(
      value =
          """
                  SELECT *
                    FROM outbox
                   WHERE status = 'PENDING'
                     AND available_at <= now()
                   ORDER BY created_at ASC
                   FOR UPDATE SKIP LOCKED
                   LIMIT :limit
                  """,
      nativeQuery = true)
  @QueryHints({
    @QueryHint(name = "jakarta.persistence.query.timeout", value = "2000"),
    @QueryHint(name = org.hibernate.jpa.HibernateHints.HINT_FETCH_SIZE, value = "200")
  })
  List<OutboxEntity> lockNextBatch(@Param("limit") int limit);

  /** Lock next batch of PENDING rows for a specific tenant. */
  @Query(
      value =
          """
                  SELECT *
                    FROM outbox
                   WHERE status = 'PENDING'
                     AND tenant_id = :tenantId
                     AND available_at <= now()
                   ORDER BY created_at ASC
                   FOR UPDATE SKIP LOCKED
                   LIMIT :limit
                  """,
      nativeQuery = true)
  @QueryHints({
    @QueryHint(name = "jakarta.persistence.query.timeout", value = "2000"),
    @QueryHint(name = org.hibernate.jpa.HibernateHints.HINT_FETCH_SIZE, value = "200")
  })
  List<OutboxEntity> lockNextBatchForTenant(
      @Param("tenantId") String tenantId, @Param("limit") int limit);

  // =========================================================================
  // State transitions
  // =========================================================================

  /** Mark a record as published. */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(
      "UPDATE OutboxEntity o "
          + "SET o.status = "
          + S_PUBLISHED
          + ", "
          + "    o.publishedAt = :when, "
          + "    o.lastError = NULL "
          + "WHERE o.id = :id")
  int markPublished(@Param("id") UUID id, @Param("when") Instant when);

  /** Mark a record as failed and reschedule with backoff. */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(
      "UPDATE OutboxEntity o "
          + "SET o.status = "
          + S_PENDING
          + ", "
          + "    o.attempts = o.attempts + 1, "
          + "    o.availableAt = :nextAttemptAt, "
          + "    o.lastError = :error "
          + "WHERE o.id = :id")
  int markFailed(
      @Param("id") UUID id,
      @Param("error") String error,
      @Param("nextAttemptAt") Instant nextAttemptAt);

  /** Quarantine a problematic record. */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(
      "UPDATE OutboxEntity o "
          + "SET o.status = "
          + S_QUARANTINED
          + ", "
          + "    o.lastError = :reason "
          + "WHERE o.id = :id")
  int quarantine(@Param("id") UUID id, @Param("reason") String reason);

  // =========================================================================
  // Housekeeping
  // =========================================================================

  /** Delete old published rows. */
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(
      "DELETE FROM OutboxEntity o "
          + "WHERE o.status = "
          + S_PUBLISHED
          + " "
          + "AND o.publishedAt < :threshold")
  int deletePublishedBefore(@Param("threshold") Instant threshold);

  // =========================================================================
  // Counters
  // =========================================================================

  long countByStatus(OutboxEntity.Status status);

  long countByStatusAndTenantId(OutboxEntity.Status status, String tenantId);

  @Query(
      "SELECT COUNT(o) FROM OutboxEntity o "
          + "WHERE o.status = "
          + S_PENDING
          + " "
          + "AND o.availableAt <= :now")
  long countPendingAvailable(@Param("now") Instant now);

  @Query(
      "SELECT COUNT(o) FROM OutboxEntity o "
          + "WHERE o.status = "
          + S_PENDING
          + " "
          + "AND o.availableAt <= :now "
          + "AND o.tenantId = :tenantId")
  long countPendingAvailableForTenant(
      @Param("tenantId") String tenantId, @Param("now") Instant now);
}
