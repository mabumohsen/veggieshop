package io.veggieshop.platform.messaging.dedupe;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

/**
 *
 *
 * <h2>Enterprise-grade consumer deduplication with replay fences</h2>
 *
 * <p><strong>Purpose:</strong> Prevent duplicate side-effects in consumers by providing idempotency
 * semantics per {@code (tenantId, eventId, version)} triplet, with configurable replay fences and
 * observability hooks (Micrometer + OpenTelemetry).
 *
 * <h3>Contract</h3>
 *
 * <ul>
 *   <li><b>Key</b>: {@code (tenantId, eventId, version)}.
 *   <li><b>TTL</b>: entries retained for at least 7 days (configurable via constructor).
 *   <li><b>Replay fences</b> (evaluated before persistence):
 *       <ul>
 *         <li><i>minAcceptedVersion</i>: reject versions lower than this floor.
 *         <li><i>replayWindow</i>: reject events older than window unless {@code operatorReplay} is
 *             true.
 *         <li><i>maxFutureSkew</i>: reject events too far in the future.
 *       </ul>
 *   <li><b>Persistence</b>: first-writer-wins UPSERT in PostgreSQL; duplicates do not re-trigger
 *       side-effects.
 *   <li><b>Fast-path</b>: optional Redis hint to short-circuit obvious duplicates (best-effort).
 * </ul>
 *
 * <h3>Storage model (PostgreSQL)</h3>
 *
 * <pre>
 * CREATE TABLE IF NOT EXISTS event_dedupe (
 *   tenant_id     TEXT       NOT NULL,
 *   event_id      TEXT       NOT NULL,
 *   version       BIGINT     NOT NULL,
 *   first_seen_at TIMESTAMPTZ NOT NULL,
 *   last_seen_at  TIMESTAMPTZ NOT NULL,
 *   expires_at    TIMESTAMPTZ NOT NULL,
 *   seen_count    INT        NOT NULL DEFAULT 1,
 *   PRIMARY KEY (tenant_id, event_id, version)
 * );
 * CREATE INDEX IF NOT EXISTS event_dedupe_expires_idx ON event_dedupe (expires_at);
 * </pre>
 *
 * <h3>Observability</h3>
 *
 * <ul>
 *   <li>OpenTelemetry span per call: {@code dedupe.check_mark}
 *   <li>Micrometer metrics:
 *       <ul>
 *         <li>{@code messaging.dedupe.accept} (tags: tenant, family, reason)
 *         <li>{@code messaging.dedupe.duplicate} (tags: tenant, family, reason)
 *         <li>{@code messaging.dedupe.quarantine} (tags: tenant, family, reason)
 *         <li>{@code messaging.dedupe.error} (tags: tenant, family, reason)
 *         <li>{@code messaging.dedupe.db.latency} (Timer; tags: tenant, family)
 *       </ul>
 * </ul>
 *
 * <p><strong>Failure policy:</strong> If the store encounters an error, the service fails
 * <em>closed</em> and returns {@link Decision#QUARANTINE_STORE_ERROR} to avoid double side-effects.
 */
public class DedupeService {

  private static final Logger log = LoggerFactory.getLogger(DedupeService.class);

  private final JdbcTemplate jdbc;

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP2",
      justification =
          "Spring-managed template is intentionally shared (bean-scoped); "
              + "field is final and never exposed.")
  private final @Nullable StringRedisTemplate redis;

  private final MeterRegistry metrics;
  private final Tracer tracer;
  private final Clock clock;
  private final ReplayPolicyProvider replayPolicyProvider;
  private final Duration ttl;

  // SQL fragments
  private static final String SQL_INSERT_DO_NOTHING =
      """
          INSERT INTO event_dedupe (
              tenant_id, event_id, version,
              first_seen_at, last_seen_at, expires_at, seen_count
          )
          VALUES (?, ?, ?, ?, ?, ?, 1)
          ON CONFLICT (tenant_id, event_id, version) DO NOTHING
          """;

  private static final String SQL_UPDATE_SEEN =
      """
            UPDATE event_dedupe
               SET last_seen_at = ?,
                   seen_count   = seen_count + 1
             WHERE tenant_id = ? AND event_id = ? AND version = ?
            """;

  /**
   * Constructs a {@code DedupeService} with a static replay policy and default telemetry wiring.
   *
   * @param jdbc JDBC template for PostgreSQL persistence (required)
   * @param redis optional Redis template used as a fast-path duplicate hint (may be {@code null})
   * @param meterRegistry Micrometer registry (required)
   * @param ttl retention for dedupe rows; minimum recommended is 7 days
   * @param minAcceptedVersion lower bound for acceptable {@code version}
   * @param replayWindow max age of {@code eventTs} accepted unless {@code operatorReplay} is true
   * @param maxFutureSkew allowable future skew for {@code eventTs}
   */
  public DedupeService(
      JdbcTemplate jdbc,
      @Nullable StringRedisTemplate redis,
      MeterRegistry meterRegistry,
      Duration ttl,
      long minAcceptedVersion,
      Duration replayWindow,
      Duration maxFutureSkew) {

    this(
        jdbc,
        redis,
        meterRegistry,
        GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.dedupe"),
        Clock.systemUTC(),
        ttl,
        new DefaultReplayPolicyProvider(minAcceptedVersion, replayWindow, maxFutureSkew));
  }

  /**
   * Constructs a {@code DedupeService} with a pluggable {@link ReplayPolicyProvider}.
   *
   * @param jdbc JDBC template (required)
   * @param redis optional Redis template (may be {@code null})
   * @param meterRegistry Micrometer registry (required)
   * @param tracer OpenTelemetry tracer (required)
   * @param clock clock source for time-based fences (required)
   * @param ttl retention window for dedupe entries (required)
   * @param replayPolicyProvider policy provider allowing tenant/family overrides (required)
   */
  public DedupeService(
      JdbcTemplate jdbc,
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
    this.replayPolicyProvider =
        Objects.requireNonNull(replayPolicyProvider, "replayPolicyProvider");

    if (ttl.compareTo(Duration.ofDays(7)) < 0) {
      log.warn(
          "Configured dedupe TTL {} is below PRD minimum (7 days). " + "Consider increasing.", ttl);
    }
  }

  /**
   * Checks replay fences and persists the triplet if accepted; returns a terminal decision.
   *
   * <p><strong>Usage</strong>:
   *
   * <pre>{@code
   * var res = dedupeService.checkAndMark(tenant, eventId, version, eventTimestamp, family, false);
   * switch (res.decision()) {
   *   case ACCEPT_FIRST_SEEN -> doSideEffects();
   *   case DUPLICATE         -> skipSideEffects();
   *   default                -> quarantine();
   * }
   * }</pre>
   *
   * @param tenantId required tenant identifier
   * @param eventId stable id across retries/replays
   * @param version monotonically increasing version per aggregate/family
   * @param eventTs producer or broker timestamp; may be {@code null} (fences that require it are
   *     skipped)
   * @param family optional event family, used for policy scoping and metrics
   * @param operatorReplay when {@code true}, bypasses the replay-window fence (audited operator
   *     action)
   * @return deduplication result with terminal {@link Decision}, persistence flag, and optional
   *     seen count
   */
  public CheckResult checkAndMark(
      String tenantId,
      String eventId,
      long version,
      @Nullable Instant eventTs,
      @Nullable String family,
      boolean operatorReplay) {

    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(eventId, "eventId");

    Span span = tracer.spanBuilder("dedupe.check_mark").setSpanKind(SpanKind.INTERNAL).startSpan();

    span.setAttribute("veggieshop.tenant_id", tenantId);
    span.setAttribute("veggieshop.event_id", hashForLog(eventId));
    span.setAttribute("veggieshop.version", version);
    if (StringUtils.hasText(family)) {
      span.setAttribute("veggieshop.family", family);
    }

    List<Tag> baseTags =
        List.of(Tag.of("tenant", tenantId), Tag.of("family", family != null ? family : "na"));
    Timer timer = Timer.builder("messaging.dedupe.db.latency").tags(baseTags).register(metrics);

    try {
      // 1) Fences
      ReplayPolicy rp = replayPolicyProvider.policyFor(tenantId, family);
      Decision fenceDecision = evaluateFences(rp, version, eventTs, operatorReplay);
      if (fenceDecision.isQuarantine()) {
        recordMetric("messaging.dedupe.quarantine", baseTags, fenceDecision.name());
        span.setStatus(StatusCode.OK, fenceDecision.name());
        span.end();
        return new CheckResult(fenceDecision, false, Optional.empty());
      }

      // 2) Redis fast-path: if known duplicate, short-circuit & best-effort bump DB counter
      if (isDuplicateInRedis(tenantId, eventId, version)) {
        recordMetric("messaging.dedupe.duplicate", baseTags, "redis_fastpath");
        span.setAttribute("veggieshop.dedupe.fastpath", true);
        bumpDbSeenCounters(timer, tenantId, eventId, version); // best-effort
        span.end();
        return new CheckResult(Decision.DUPLICATE, false, Optional.empty());
      }

      // 3) First-writer-wins insert
      Instant now = clock.instant();
      Instant expiresAt = now.plus(ttl);

      long start = System.nanoTime();
      int inserted =
          safeUpdate(SQL_INSERT_DO_NOTHING, tenantId, eventId, version, now, now, expiresAt);
      timer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);

      if (inserted == 1) {
        // First time observed
        writeRedisFlag(tenantId, eventId, version, ttl);
        recordMetric("messaging.dedupe.accept", baseTags, "first_seen");
        span.setStatus(StatusCode.OK);
        span.end();
        return new CheckResult(Decision.ACCEPT_FIRST_SEEN, true, Optional.of(1L));
      }

      // 4) Conflict path → duplicate; bump counters & emit hint
      bumpDbSeenCounters(timer, tenantId, eventId, version);
      writeRedisFlag(tenantId, eventId, version, ttl);
      recordMetric("messaging.dedupe.duplicate", baseTags, "db_conflict");
      span.setStatus(StatusCode.OK);
      span.end();
      return new CheckResult(Decision.DUPLICATE, false, Optional.empty());

    } catch (Exception e) {
      // Fail-closed to avoid double side-effects when store is unhealthy
      span.recordException(e);
      span.setStatus(StatusCode.ERROR, safeMessage(e));
      span.end();
      recordMetric("messaging.dedupe.error", baseTags, e.getClass().getSimpleName());
      log.error(
          "dedupe_error tenant={} family={} errClass={} msg={}",
          tenantId,
          family,
          e.getClass().getSimpleName(),
          safeMessage(e));
      return new CheckResult(Decision.QUARANTINE_STORE_ERROR, false, Optional.empty());
    }
  }

  // -------------------------------------------------------------------------
  // Replay fences
  // -------------------------------------------------------------------------

  /**
   * Evaluates replay fences based on the provided policy and event attributes.
   *
   * @param policy replay policy
   * @param version event version
   * @param eventTs event timestamp (nullable)
   * @param operatorReplay operator-approved replay toggle
   * @return fence decision (may be quarantine or accept)
   */
  private Decision evaluateFences(
      ReplayPolicy policy, long version, @Nullable Instant eventTs, boolean operatorReplay) {

    if (version < policy.minAcceptedVersion()) {
      return Decision.QUARANTINE_TOO_OLD_VERSION;
    }
    if (eventTs != null) {
      Instant now = clock.instant();
      if (eventTs.isAfter(now.plus(policy.maxFutureSkew()))) {
        return Decision.QUARANTINE_FUTURE_SKEW;
      }
      if (!operatorReplay && eventTs.isBefore(now.minus(policy.replayWindow()))) {
        return Decision.QUARANTINE_OUTSIDE_REPLAY_WINDOW;
      }
    }
    return Decision.ACCEPT_FENCES_OK;
  }

  // -------------------------------------------------------------------------
  // Redis helpers (optional)
  // -------------------------------------------------------------------------

  /**
   * Checks whether the triplet is already observed using a Redis hint.
   *
   * @param tenantId tenant identifier
   * @param eventId event id
   * @param version version
   * @return {@code true} if a fast-path duplicate hint is present; {@code false} otherwise
   */
  private boolean isDuplicateInRedis(String tenantId, String eventId, long version) {
    if (redis == null) {
      return false;
    }
    String key = redisKey(tenantId, eventId, version);
    try {
      Boolean exists = redis.hasKey(key);
      return Boolean.TRUE.equals(exists);
    } catch (Exception ignored) {
      // Do not fail dedupe on Redis issues
      return false;
    }
  }

  /**
   * Writes a Redis flag for the observed triplet (best-effort).
   *
   * @param tenantId tenant identifier
   * @param eventId event id
   * @param version version
   * @param ttl entry TTL
   */
  private void writeRedisFlag(String tenantId, String eventId, long version, Duration ttl) {
    if (redis == null) {
      return;
    }
    String key = redisKey(tenantId, eventId, version);
    try {
      redis.opsForValue().setIfAbsent(key, "1", ttl);
    } catch (Exception ignored) {
      // Best-effort; DB remains the source of truth
    }
  }

  /**
   * Builds a compact Redis key using sha256 of {@code tenant|eventId|version}.
   *
   * @param tenantId tenant identifier
   * @param eventId event id
   * @param version version
   * @return namespaced compact key
   */
  private String redisKey(String tenantId, String eventId, long version) {
    String material = tenantId + "|" + eventId + "|" + version;
    String digest = sha256Hex(material);
    return "tenant:" + tenantId + ":dedupe:" + digest;
  }

  // -------------------------------------------------------------------------
  // DB helpers
  // -------------------------------------------------------------------------

  /**
   * Best-effort counter bump on duplicate paths.
   *
   * @param timer latency timer
   * @param tenantId tenant identifier
   * @param eventId event id
   * @param version version
   */
  private void bumpDbSeenCounters(Timer timer, String tenantId, String eventId, long version) {
    try {
      long start = System.nanoTime();
      int rows = safeUpdate(SQL_UPDATE_SEEN, clock.instant(), tenantId, eventId, version);
      timer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);
      if (rows == 0 && log.isDebugEnabled()) {
        // Rare (race + TTL purge between insert & update)
        log.debug(
            "dedupe_seen_update_noop tenant={} eventIdHash={} version={}",
            tenantId,
            hashForLog(eventId),
            version);
      }
    } catch (Exception e) {
      // Non-fatal; counters are best-effort
      if (log.isDebugEnabled()) {
        log.debug(
            "dedupe_seen_update_error tenant={} eventIdHash={} version={} err={}",
            tenantId,
            hashForLog(eventId),
            version,
            safeMessage(e));
      }
    }
  }

  /**
   * Executes a JDBC update with duplicate-key tolerance.
   *
   * @param sql SQL text
   * @param args bind arguments
   * @return affected rows; {@code 0} on duplicate-key
   * @throws DataAccessException on non-duplicate data access errors
   */
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

  /**
   * Increments a Micrometer counter with base tags and a {@code reason} tag.
   *
   * @param name metric name
   * @param baseTags base tags (e.g., tenant, family)
   * @param reason value for the {@code reason} tag
   */
  private void recordMetric(String name, List<Tag> baseTags, String reason) {
    List<Tag> tags = new ArrayList<>(baseTags.size() + 1);
    tags.addAll(baseTags);
    tags.add(Tag.of("reason", reason));
    metrics.counter(name, tags).increment();
  }

  /**
   * Computes a SHA-256 hex digest for the given string.
   *
   * @param s input string
   * @return lower-case hex digest or fallback hash on error
   */
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

  /**
   * Returns a short, log-safe identifier (first 12 hex chars of SHA-256).
   *
   * @param s raw id
   * @return short hash prefix
   */
  private static String hashForLog(String s) {
    String h = sha256Hex(s);
    return h.substring(0, Math.min(12, h.length()));
  }

  /**
   * Produces a bounded-length exception message safe for logs.
   *
   * @param t throwable
   * @return sanitized message
   */
  private static String safeMessage(Throwable t) {
    String m = t.getMessage();
    if (m == null) {
      return t.getClass().getSimpleName();
    }
    return m.length() > 200 ? m.substring(0, 200) + "..." : m;
  }

  // -------------------------------------------------------------------------
  // Public API types
  // -------------------------------------------------------------------------

  /** Terminal decision for a dedupe check. */
  public enum Decision {
    /** Fences OK; first observation → proceed with side-effects; row persisted. */
    ACCEPT_FIRST_SEEN,

    /** Fences OK; already observed → skip side-effects. */
    DUPLICATE,

    /** Fences OK; internal pre-persistence acceptance (non-terminal for callers). */
    ACCEPT_FENCES_OK,

    /** Event version is below the minimum accepted version fence. */
    QUARANTINE_TOO_OLD_VERSION,

    /** Event timestamp is outside the allowed replay window and not operator-approved. */
    QUARANTINE_OUTSIDE_REPLAY_WINDOW,

    /** Event timestamp is too far in the future beyond the allowed skew. */
    QUARANTINE_FUTURE_SKEW,

    /** Store was unavailable or errored; fail-closed to avoid duplicate side-effects. */
    QUARANTINE_STORE_ERROR;

    /**
     * Indicates whether this decision represents a quarantine (reject) state.
     *
     * @return {@code true} if the decision represents a quarantine (reject) state.
     */
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
   * @param decision terminal decision
   * @param persisted {@code true} if a new row was inserted (first observation)
   * @param seenCount optional count when available (e.g., on first insert)
   */
  public record CheckResult(Decision decision, boolean persisted, Optional<Long> seenCount) {}

  /**
   * Replay policy describing fences for a tenant/family.
   *
   * @param minAcceptedVersion version floor; lower versions are rejected
   * @param replayWindow window where old events are still acceptable
   * @param maxFutureSkew allowable future skew for event timestamps
   */
  public record ReplayPolicy(
      long minAcceptedVersion, Duration replayWindow, Duration maxFutureSkew) {}

  /** Provider for replay policies, allowing per-tenant/family overrides. */
  public interface ReplayPolicyProvider {
    /**
     * Resolves the replay policy for the given tenant and optional family.
     *
     * @param tenantId tenant identifier
     * @param family optional family (may be {@code null})
     * @return resolved replay policy (never {@code null})
     */
    ReplayPolicy policyFor(String tenantId, @Nullable String family);
  }

  /** Default provider returning a single static policy for all tenants/families. */
  public static final class DefaultReplayPolicyProvider implements ReplayPolicyProvider {
    private final ReplayPolicy policy;

    /**
     * Constructs a static {@link ReplayPolicyProvider}.
     *
     * @param minAcceptedVersion version floor
     * @param replayWindow replay acceptance window
     * @param maxFutureSkew allowable future skew
     */
    public DefaultReplayPolicyProvider(
        long minAcceptedVersion, Duration replayWindow, Duration maxFutureSkew) {
      this.policy = new ReplayPolicy(minAcceptedVersion, replayWindow, maxFutureSkew);
    }

    @Override
    public ReplayPolicy policyFor(String tenantId, @Nullable String family) {
      return policy;
    }
  }
}
