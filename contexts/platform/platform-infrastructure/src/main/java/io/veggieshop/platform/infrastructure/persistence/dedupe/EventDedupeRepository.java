package io.veggieshop.platform.infrastructure.persistence.dedupe;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * EventDedupeRepository
 *
 * <p>Repository for the consumer de-duplication store (PostgreSQL 15+). Aligns with PRD v2.0
 * exactly-once effects at the consumer layer: - Natural composite key: (tenant_id, event_id,
 * event_version) - TTL-based retention (>= 7d) via expires_at - No PII; operational metadata for
 * observability
 *
 * <p>Recommended usage pattern: 1) In a consumer, attempt {@link #markProcessedIfAbsent(String,
 * UUID, long, Instant, Duration, String, String, String, String)}. 2) If returns true → proceed
 * with side effects (or vice versa when side effects are idempotent on their own). 3) If false →
 * duplicate delivery; skip or route to idempotent path.
 *
 * <p>Notes: - Uses PostgreSQL's ON CONFLICT to guarantee atomic "insert if absent". - Batch TTL
 * cleanup is exposed via {@link #deleteExpiredBefore(Instant, int)}. - Keep the call inside a
 * transaction that also wraps your side-effects when possible.
 */
@Repository
public interface EventDedupeRepository
    extends JpaRepository<EventDedupeEntity, EventDedupeEntity.EventDedupeKey> {

  /* =======================================================================
  Atomic insert-if-absent (gate) using native PostgreSQL upsert
  ======================================================================= */

  @Modifying(flushAutomatically = false, clearAutomatically = false)
  @Transactional
  @Query(
      value =
          """
        INSERT INTO event_dedupe
            (tenant_id, event_id, event_version, processed_at, expires_at,
             consumer, event_family, trace_id, payload_fingerprint)
        VALUES
            (:tenantId, :eventId, :eventVersion, :processedAt, :expiresAt,
             :consumer, :eventFamily, :traceId, :payloadFingerprint)
        ON CONFLICT (tenant_id, event_id, event_version) DO NOTHING
        """,
      nativeQuery = true)
  int insertIgnoreConflict(
      @Param("tenantId") String tenantId,
      @Param("eventId") UUID eventId,
      @Param("eventVersion") long eventVersion,
      @Param("processedAt") Instant processedAt,
      @Param("expiresAt") Instant expiresAt,
      @Param("consumer") String consumer,
      @Param("eventFamily") String eventFamily,
      @Param("traceId") String traceId,
      @Param("payloadFingerprint") String payloadFingerprint);

  /** Atomically mark the event as processed if absent. Returns true iff a new row was inserted. */
  @Transactional
  default boolean markProcessedIfAbsent(
      String tenantId,
      UUID eventId,
      long eventVersion,
      Instant now,
      Duration ttl,
      String consumer,
      String eventFamily,
      String traceId,
      String payloadFingerprint) {
    if (ttl == null || ttl.isNegative() || ttl.isZero()) {
      ttl = EventDedupeEntity.DEFAULT_TTL; // safety net (>= 7d per PRD)
    }
    final int inserted =
        insertIgnoreConflict(
            tenantId,
            eventId,
            eventVersion,
            now,
            now.plus(ttl),
            consumer,
            eventFamily,
            traceId,
            payloadFingerprint);
    return inserted == 1;
  }

  /** Convenience overload using the entity's DEFAULT_TTL. */
  @Transactional
  default boolean markProcessedIfAbsent(
      String tenantId,
      UUID eventId,
      long eventVersion,
      Instant now,
      String consumer,
      String eventFamily,
      String traceId,
      String payloadFingerprint) {
    return markProcessedIfAbsent(
        tenantId,
        eventId,
        eventVersion,
        now,
        EventDedupeEntity.DEFAULT_TTL,
        consumer,
        eventFamily,
        traceId,
        payloadFingerprint);
  }

  /* =======================================================================
  TTL management / housekeeping
  ======================================================================= */

  /**
   * Extend TTL (expires_at) only if the new value is further in the future. Returns number of rows
   * updated (0 or 1).
   */
  @Modifying(flushAutomatically = false, clearAutomatically = false)
  @Transactional
  @Query(
      value =
          """
        UPDATE event_dedupe
           SET expires_at = :newExpiresAt
         WHERE tenant_id = :tenantId
           AND event_id = :eventId
           AND event_version = :eventVersion
           AND expires_at < :newExpiresAt
        """,
      nativeQuery = true)
  int extendTtl(
      @Param("tenantId") String tenantId,
      @Param("eventId") UUID eventId,
      @Param("eventVersion") long eventVersion,
      @Param("newExpiresAt") Instant newExpiresAt);

  /**
   * Delete expired rows in small batches for predictable vacuum/IO behavior. Returns number of rows
   * deleted in this pass.
   *
   * <p>Uses ctid to avoid large DELETE w/o LIMIT. Repeat until returns 0.
   */
  @Modifying(flushAutomatically = false, clearAutomatically = false)
  @Transactional
  @Query(
      value =
          """
        WITH del AS (
            SELECT ctid
              FROM event_dedupe
             WHERE expires_at < :cutoff
             ORDER BY expires_at
             LIMIT :limit
        )
        DELETE FROM event_dedupe d
         USING del
         WHERE d.ctid = del.ctid
        """,
      nativeQuery = true)
  int deleteExpiredBefore(@Param("cutoff") Instant cutoff, @Param("limit") int limit);

  /* =======================================================================
  Lightweight ops/observability helpers
  ======================================================================= */

  default boolean exists(String tenantId, UUID eventId, long eventVersion) {
    return existsById(new EventDedupeEntity.EventDedupeKey(tenantId, eventId, eventVersion));
  }

  default Optional<EventDedupeEntity> get(String tenantId, UUID eventId, long eventVersion) {
    return findById(new EventDedupeEntity.EventDedupeKey(tenantId, eventId, eventVersion));
  }

  @Query(value = "select count(*) from event_dedupe where expires_at < :cutoff", nativeQuery = true)
  long countExpiredBefore(@Param("cutoff") Instant cutoff);

  @Query(
      value = "select count(*) from event_dedupe where event_family = :family",
      nativeQuery = true)
  long countByFamily(@Param("family") String eventFamily);
}
