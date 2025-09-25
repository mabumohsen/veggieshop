package io.veggieshop.platform.messaging.dedupe;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.data.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * DedupeService provides consumer-side idempotency guarantees with replay fences.
 *
 * <p>Contract (PRD-aligned):
 * <ul>
 *   <li>Key = (tenantId, eventId, version). TTL >= 7d (configurable).</li>
 *   <li>Replay fences:
 *     <ul>
 *       <li>Reject events older than {@code minAcceptedVersion} (QUARANTINE_TOO_OLD_VERSION).</li>
 *       <li>Reject events outside a {@code replayWindow} unless operator-replay is enabled
 *           (QUARANTINE_OUTSIDE_REPLAY_WINDOW).</li>
 *       <li>Reject events with future timestamps beyond {@code maxFutureSkew} (QUARANTINE_FUTURE_SKEW).</li>
 *     </ul>
 *   </li>
 *   <li>Exactly-once effect is realized by first-writer-wins UPSERT; duplicates
 *       do not re-execute side effects.</li>
 *   <li>Observability: OpenTelemetry span per check, Micrometer counters/timers.</li>
 * </ul>
 *
 * <p>Storage model (PostgreSQL):
 * <pre>
 * CREATE TABLE IF NOT EXISTS event_dedupe (
 *   tenant_id   TEXT    NOT NULL,
 *   event_id    TEXT    NOT NULL,
 *   version     BIGINT  NOT NULL,
 *   first_seen_at  TIMESTAMPTZ NOT NULL,
 *   last_seen_at   TIMESTAMPTZ NOT NULL,
 *   expires_at     TIMESTAMPTZ NOT NULL,
 *   seen_count     INT NOT NULL DEFAULT 1,
 *   PRIMARY KEY (tenant_id, event_id, version)
 * );
 * CREATE INDEX IF NOT EXISTS event_dedupe_expires_idx ON event_dedupe (expires_at);
 * </pre>
 *
 * <p>Fast-path cache (optional): a small Redis key per triplet reduces DB hits under hot replays.
 */
public class DedupeService {

    private static final Logger log = LoggerFactory.getLogger(DedupeService.class);

    private final JdbcTemplate jdbc;
    private final @Nullable StringRedisTemplate redis;
    private final MeterRegistry metrics;
    private final Tracer tracer;
    private final Clock clock;
    private final ReplayPolicyProvider replayPolicyProvider;
    private final Duration ttl;

    // SQL fragments
    private static final String SQL_INSERT_DO_NOTHING = """
        INSERT INTO event_dedupe (tenant_id, event_id, version, first_seen_at, last_seen_at, expires_at, seen_count)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT (tenant_id, event_id, version) DO NOTHING
        """;

    private static final String SQL_UPDATE_SEEN = """
        UPDATE event_dedupe
           SET last_seen_at = ?,
               seen_count   = seen_count + 1
         WHERE tenant_id = ? AND event_id = ? AND version = ?
        """;

    public DedupeService(JdbcTemplate jdbc,
                         @Nullable StringRedisTemplate redis,
                         MeterRegistry meterRegistry,
                         Duration ttl,
                         long minAcceptedVersion,
                         Duration replayWindow,
                         Duration maxFutureSkew) {

        this(jdbc,
                redis,
                meterRegistry,
                io.opentelemetry.api.GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.dedupe"),
                java.time.Clock.systemUTC(),
                ttl,
                new DefaultReplayPolicyProvider(minAcceptedVersion, replayWindow, maxFutureSkew));
    }

    public DedupeService(JdbcTemplate jdbc,
                         @Nullable StringRedisTemplate redis,
                         MeterRegistry meterRegistry,
                         Tracer tracer,
                         Clock clock,
                         Duration ttl,
                         ReplayPolicyProvider replayPolicyProvider) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.redis = redis; // optional
        this.metrics = Objects.requireNonNull(meterRegistry, "meterRegistry");
        this.tracer = Objects.requireNonNull(tracer, "tracer");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.replayPolicyProvider = Objects.requireNonNull(replayPolicyProvider, "replayPolicyProvider");
        if (ttl.compareTo(Duration.ofDays(7)) < 0) {
            log.warn("Configured dedupe TTL {} is below PRD minimum (7 days). Consider increasing.", ttl);
        }
    }

    /**
     * Check replay fences and mark the triplet (tenantId, eventId, version) as processed if accepted.
     *
     * <p>Usage:
     * <pre>
     *   var res = dedupeService.checkAndMark(tenant, eventId, version, eventTimestamp, family, false);
     *   switch (res.decision()) {
     *     case ACCEPT_FIRST_SEEN -> doSideEffects();
     *     case DUPLICATE         -> skipSideEffects();
     *     default                -> quarantine();
     *   }
     * </pre>
     *
     * @param tenantId   required tenant id claim
     * @param eventId    event identity stable across retries/replays
     * @param version    monotonically increasing version per aggregate/family
     * @param eventTs    event production time (broker or producer). May be null; fences that need it are skipped.
     * @param family     optional event family (used to scope policy overrides/metrics)
     * @param operatorReplay if true, bypasses the replay window fence (used by approved operator replays)
     */
    public CheckResult checkAndMark(
            String tenantId,
            String eventId,
            long version,
            @Nullable Instant eventTs,
            @Nullable String family,
            boolean operatorReplay
    ) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(eventId, "eventId");

        Span span = tracer.spanBuilder("dedupe.check_mark")
                .setSpanKind(SpanKind.INTERNAL)
                .startSpan();

        span.setAttribute("veggieshop.tenant_id", tenantId);
        span.setAttribute("veggieshop.event_id", hashForLog(eventId));
        span.setAttribute("veggieshop.version", version);
        if (StringUtils.hasText(family)) {
            span.setAttribute("veggieshop.family", family);
        }

        List<Tag> baseTags = List.of(
                Tag.of("tenant", tenantId),
                Tag.of("family", family != null ? family : "na")
        );
        Timer timer = Timer.builder("messaging.dedupe.db.latency").tags(baseTags).register(metrics);

        try {
            // 1) Evaluate replay fences
            ReplayPolicy rp = replayPolicyProvider.policyFor(tenantId, family);
            Decision fenceDecision = evaluateFences(rp, version, eventTs, operatorReplay);
            if (fenceDecision.isQuarantine()) {
                recordMetric("messaging.dedupe.quarantine", baseTags, fenceDecision.name());
                span.setStatus(StatusCode.OK, fenceDecision.name());
                span.end();
                return new CheckResult(fenceDecision, false, Optional.empty());
            }

            // 2) Redis fast-path (optional). If already seen, short-circuit to duplicate.
            if (isDuplicateInRedis(tenantId, eventId, version)) {
                recordMetric("messaging.dedupe.duplicate", baseTags, "redis_fastpath");
                span.setAttribute("veggieshop.dedupe.fastpath", true);
                // We still bump DB counters (best-effort) to track observed duplicates
                bumpDbSeenCounters(timer, tenantId, eventId, version);
                span.end();
                return new CheckResult(Decision.DUPLICATE, false, Optional.empty());
            }

            // 3) DB insert (first-writer-wins)
            Instant now = clock.instant();
            Instant expiresAt = now.plus(ttl);

            long start = System.nanoTime();
            int inserted = safeUpdate(SQL_INSERT_DO_NOTHING,
                    tenantId, eventId, version, now, now, expiresAt);
            timer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);

            if (inserted == 1) {
                // First time seen
                writeRedisFlag(tenantId, eventId, version, ttl);
                recordMetric("messaging.dedupe.accept", baseTags, "first_seen");
                span.setStatus(StatusCode.OK);
                span.end();
                return new CheckResult(Decision.ACCEPT_FIRST_SEEN, true, Optional.of(1L));
            }

            // 4) Conflict path → duplicate; bump counters
            bumpDbSeenCounters(timer, tenantId, eventId, version);
            writeRedisFlag(tenantId, eventId, version, ttl);
            recordMetric("messaging.dedupe.duplicate", baseTags, "db_conflict");
            span.setStatus(StatusCode.OK);
            span.end();
            return new CheckResult(Decision.DUPLICATE, false, Optional.empty());

        } catch (Exception e) {
            // Fail closed or open? For dedupe we default to FAIL-CLOSED (i.e., QUARANTINE)
            // to avoid double side-effects when store is down.
            span.recordException(e);
            span.setStatus(StatusCode.ERROR, safeMessage(e));
            span.end();
            recordMetric("messaging.dedupe.error", baseTags, e.getClass().getSimpleName());
            log.error("dedupe_error tenant={} family={} errClass={} msg={}",
                    tenantId, family, e.getClass().getSimpleName(), safeMessage(e));
            return new CheckResult(Decision.QUARANTINE_STORE_ERROR, false, Optional.empty());
        }
    }

    // -------------------------------------------------------------------------
    // Replay fences
    // -------------------------------------------------------------------------

    private Decision evaluateFences(ReplayPolicy policy,
                                    long version,
                                    @Nullable Instant eventTs,
                                    boolean operatorReplay) {
        if (version < policy.minAcceptedVersion()) {
            return Decision.QUARANTINE_TOO_OLD_VERSION;
        }
        if (eventTs != null) {
            Instant now = clock.instant();

            // Future skew
            if (eventTs.isAfter(now.plus(policy.maxFutureSkew()))) {
                return Decision.QUARANTINE_FUTURE_SKEW;
            }

            // Replay window unless operator-approved replay
            if (!operatorReplay && eventTs.isBefore(now.minus(policy.replayWindow()))) {
                return Decision.QUARANTINE_OUTSIDE_REPLAY_WINDOW;
            }
        }
        return Decision.ACCEPT_FENCES_OK;
    }

    // -------------------------------------------------------------------------
    // Redis helpers (optional)
    // -------------------------------------------------------------------------

    private boolean isDuplicateInRedis(String tenantId, String eventId, long version) {
        if (redis == null) return false;
        String key = redisKey(tenantId, eventId, version);
        try {
            Boolean exists = redis.hasKey(key);
            return Boolean.TRUE.equals(exists);
        } catch (Exception ignored) {
            // Do not fail dedupe on Redis issues
            return false;
        }
    }

    private void writeRedisFlag(String tenantId, String eventId, long version, Duration ttl) {
        if (redis == null) return;
        String key = redisKey(tenantId, eventId, version);
        try {
            redis.opsForValue().setIfAbsent(key, "1", ttl);
        } catch (Exception ignored) {
            // Best-effort; DB remains the source of truth
        }
    }

    private String redisKey(String tenantId, String eventId, long version) {
        // Use a compact, length-safe key: sha256(tenant|eventId|version)
        String material = tenantId + "|" + eventId + "|" + version;
        String digest = sha256Hex(material);
        return "tenant:" + tenantId + ":dedupe:" + digest;
    }

    // -------------------------------------------------------------------------
    // DB helpers
    // -------------------------------------------------------------------------

    private void bumpDbSeenCounters(Timer timer, String tenantId, String eventId, long version) {
        try {
            long start = System.nanoTime();
            int rows = safeUpdate(SQL_UPDATE_SEEN, clock.instant(), tenantId, eventId, version);
            timer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);
            if (rows == 0 && log.isDebugEnabled()) {
                // This should be rare (insert raced and lost + delete by TTL between operations)
                log.debug("dedupe_seen_update_noop tenant={} eventIdHash={} version={}",
                        tenantId, hashForLog(eventId), version);
            }
        } catch (Exception e) {
            // Non-fatal; counters are best-effort
            if (log.isDebugEnabled()) {
                log.debug("dedupe_seen_update_error tenant={} eventIdHash={} version={} err={}",
                        tenantId, hashForLog(eventId), version, safeMessage(e));
            }
        }
    }

    private int safeUpdate(String sql, Object... args) {
        try {
            return jdbc.update(sql, args);
        } catch (DuplicateKeyException dke) {
            return 0;
        } catch (DataAccessException dae) {
            throw dae;
        }
    }

    // -------------------------------------------------------------------------
    // Metrics & utils
    // -------------------------------------------------------------------------

    private void recordMetric(String name, List<Tag> baseTags, String reason) {
        var tags = new ArrayList<Tag>(baseTags.size() + 1);
        tags.addAll(baseTags);
        tags.add(Tag.of("reason", reason));
        metrics.counter(name, tags).increment();  // ← يقبل Iterable<Tag>
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (Exception e) {
            // Should never happen; fallback to sanitized string
            return Integer.toHexString(s.hashCode());
        }
    }

    private static String hashForLog(String s) {
        // Log a short prefix only; avoid leaking raw IDs across boundaries
        String h = sha256Hex(s);
        return h.substring(0, 12);
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        if (m == null) return t.getClass().getSimpleName();
        return m.length() > 200 ? m.substring(0, 200) + "..." : m;
    }

    // -------------------------------------------------------------------------
    // Public API types
    // -------------------------------------------------------------------------

    /**
     * The dedupe decision outcome.
     */
    public enum Decision {
        /** Fences OK, first time we see the triplet → proceed with side effects, dedupe persisted. */
        ACCEPT_FIRST_SEEN,

        /** Fences OK, but we have already seen the triplet → skip side effects. */
        DUPLICATE,

        /** Fences OK; used internally before DB step to indicate acceptance (not a terminal user-facing state). */
        ACCEPT_FENCES_OK,

        /** Event version is below the minimum accepted version fence. */
        QUARANTINE_TOO_OLD_VERSION,

        /** Event timestamp is outside the allowed replay window (and not operator-approved). */
        QUARANTINE_OUTSIDE_REPLAY_WINDOW,

        /** Event timestamp is too far in the future beyond the allowed skew. */
        QUARANTINE_FUTURE_SKEW,

        /** The dedupe store was unavailable or errored → fail-closed and quarantine. */
        QUARANTINE_STORE_ERROR;

        public boolean isQuarantine() {
            return this == QUARANTINE_TOO_OLD_VERSION
                    || this == QUARANTINE_OUTSIDE_REPLAY_WINDOW
                    || this == QUARANTINE_FUTURE_SKEW
                    || this == QUARANTINE_STORE_ERROR;
        }
    }

    /**
     * Result of a dedupe check.
     *
     * @param decision  terminal decision
     * @param persisted true if we inserted a new dedupe row (first seen)
     * @param seenCount optional count (when available)
     */
    public record CheckResult(Decision decision, boolean persisted, Optional<Long> seenCount) {}

    /**
     * Replay policy for a given tenant/family.
     */
    public record ReplayPolicy(long minAcceptedVersion, Duration replayWindow, Duration maxFutureSkew) {}

    /**
     * Provider for replay policies. Allows per-tenant/family overrides.
     * Implementations may consult configuration, a DB table, or an in-memory map.
     */
    public interface ReplayPolicyProvider {
        ReplayPolicy policyFor(String tenantId, @Nullable String family);
    }

    /**
     * Default provider that returns a single static policy for all tenants/families.
     */
    public static final class DefaultReplayPolicyProvider implements ReplayPolicyProvider {
        private final ReplayPolicy policy;

        public DefaultReplayPolicyProvider(long minAcceptedVersion,
                                           Duration replayWindow,
                                           Duration maxFutureSkew) {
            this.policy = new ReplayPolicy(minAcceptedVersion, replayWindow, maxFutureSkew);
        }

        @Override
        public ReplayPolicy policyFor(String tenantId, @Nullable String family) {
            return policy;
        }
    }
}
