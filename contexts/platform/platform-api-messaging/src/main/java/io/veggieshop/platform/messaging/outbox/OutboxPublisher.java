package io.veggieshop.platform.messaging.outbox;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.veggieshop.platform.messaging.kafka.ReliablePublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.DataClassRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.Nullable;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.lang.Math.min;

public class OutboxPublisher implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisher.class);
    private static final TypeReference<Map<String, String>> MAP_STRING_STRING = new TypeReference<>() {};

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final ReliablePublisher reliablePublisher;
    private final ObjectMapper objectMapper;
    private final MeterRegistry metrics;
    private final Tracer tracer;
    private final Clock clock;
    private final ExecutorService vthreads;
    private final Random jitter;

    private final String table;
    private final int batchSize;
    private final int parallelism;
    private final int maxAttempts;
    private final Duration baseBackoff;
    private final Duration maxBackoff;

    public OutboxPublisher(JdbcTemplate jdbc,
                           TransactionTemplate tx,
                           ReliablePublisher reliablePublisher,
                           ObjectMapper objectMapper,
                           MeterRegistry meterRegistry,
                           Clock clock,
                           String table,
                           int batchSize,
                           int parallelism,
                           int maxAttempts,
                           Duration baseBackoff,
                           Duration maxBackoff) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.tx = Objects.requireNonNull(tx, "tx");
        this.reliablePublisher = Objects.requireNonNull(reliablePublisher, "reliablePublisher");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.metrics = Objects.requireNonNull(meterRegistry, "meterRegistry");
        this.tracer = GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.outbox");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.table = Objects.requireNonNull(table, "table");
        this.batchSize = batchSize;
        this.parallelism = parallelism;
        this.maxAttempts = maxAttempts;
        this.baseBackoff = Objects.requireNonNull(baseBackoff, "baseBackoff");
        this.maxBackoff = Objects.requireNonNull(maxBackoff, "maxBackoff");

        this.vthreads = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().name("outbox-pub-", 0).factory());
        this.jitter = new Random();
        sanityLogConfig();
    }

    private void sanityLogConfig() {
        log.info("outbox_publisher_init table={} batchSize={} parallelism={} maxAttempts={} baseBackoff={} maxBackoff={}",
                table, batchSize, parallelism, maxAttempts, baseBackoff, maxBackoff);
    }

    /** يشغّل دورة drain واحدة ويُرجع عدد الرسائل التي نُشرت بنجاح. */
    public int drainOnce() {
        Span batchSpan = tracer.spanBuilder("outbox.drain").setSpanKind(SpanKind.INTERNAL).startSpan();

        Timer dbTimer = Timer.builder("outbox.db.latency").register(metrics);
        Timer publishTimer = Timer.builder("outbox.publish.latency").register(metrics);

        try {
            long t0 = System.nanoTime();
            List<OutboxRow> batch = tx.execute(status -> claimBatch(batchSize));
            dbTimer.record(System.nanoTime() - t0, TimeUnit.NANOSECONDS);

            if (batch == null || batch.isEmpty()) {
                metrics.counter("outbox.batch.empty").increment();
                batchSpan.end();
                return 0;
            }

            int window = min(parallelism, batch.size());
            var semaphore = new java.util.concurrent.Semaphore(window);
            var publishedCounter = new java.util.concurrent.atomic.AtomicInteger();
            var failedCounter = new java.util.concurrent.atomic.AtomicInteger();

            for (OutboxRow row : batch) {
                semaphore.acquireUninterruptibly();
                vthreads.submit(() -> {
                    try {
                        long start = System.nanoTime();
                        publishOne(row);
                        publishTimer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);
                        publishedCounter.incrementAndGet();
                    } catch (Exception ex) {
                        failedCounter.incrementAndGet();
                        log.debug("outbox_publish_task_error id={} class={} msg={}",
                                row.id(), ex.getClass().getSimpleName(), safeMsg(ex));
                    } finally {
                        semaphore.release();
                    }
                });
            }

            semaphore.acquireUninterruptibly(window);
            semaphore.release(window);

            int ok = publishedCounter.get();
            int ko = failedCounter.get();
            metrics.counter("outbox.records.published").increment(ok);
            metrics.counter("outbox.records.failed").increment(ko);
            metrics.summary("outbox.batch.size").record(batch.size());
            batchSpan.setAttribute("outbox.batch.size", batch.size());
            batchSpan.setAttribute("outbox.batch.ok", ok);
            batchSpan.setAttribute("outbox.batch.ko", ko);
            batchSpan.end();
            return ok;
        } catch (Exception e) {
            batchSpan.recordException(e);
            batchSpan.setStatus(StatusCode.ERROR, safeMsg(e));
            batchSpan.end();
            metrics.counter("outbox.batch.error", Tags.of("class", e.getClass().getSimpleName())).increment();
            log.error("outbox_batch_error class={} msg={}", e.getClass().getSimpleName(), safeMsg(e));
            return 0;
        }
    }

    private List<OutboxRow> claimBatch(int limit) {
        String sql = """
            WITH cte AS (
               SELECT id
                 FROM %s
                WHERE status IN ('NEW','RETRY')
                  AND next_attempt_at <= now()
                ORDER BY priority DESC, id ASC
                FOR UPDATE SKIP LOCKED
                LIMIT ?
            )
            UPDATE %s o
               SET status     = 'IN_PROGRESS',
                   claimed_by = ?,
                   claimed_at = now(),
                   attempts   = o.attempts + 1,
                   updated_at = now()
              WHERE o.id IN (SELECT id FROM cte)
            RETURNING o.id, o.tenant_id, o.topic, o.key_bytes, o.value_bytes, o.headers_json,
                      o.event_id, o.entity_version, o.attempts, o.status, o.next_attempt_at, o.created_at
            """.formatted(table, table);

        String workerId = workerId();
        List<OutboxRow> rows = jdbc.query(sql, new DataClassRowMapper<>(OutboxRow.class), limit, workerId);
        metrics.summary("outbox.claimed").record(rows.size());
        return rows;
    }

    private void publishOne(OutboxRow row) {
        Span span = tracer.spanBuilder("outbox.publish").setSpanKind(SpanKind.PRODUCER).startSpan();
        span.setAttribute("outbox.id", row.id());
        span.setAttribute("outbox.tenant", row.tenantId());
        span.setAttribute("outbox.topic", row.topic());
        if (row.entityVersion() != null) span.setAttribute("outbox.entity_version", row.entityVersion());
        if (StringUtils.hasText(row.eventId())) span.setAttribute("outbox.event_id_hash", hashForLog(row.eventId()));

        try {
            byte[] key = row.keyBytes();
            byte[] value = row.valueBytes();
            Map<String, String> headers = parseHeaders(row.headersJson());

            headers = putIfAbsent(headers, "x-tenant-id", row.tenantId());
            if (row.entityVersion() != null) headers = putIfAbsent(headers, "x-entity-version", Long.toString(row.entityVersion()));
            if (StringUtils.hasText(row.eventId())) headers = putIfAbsent(headers, "x-event-id", row.eventId());

            var opts = ReliablePublisher.PublisherOptions.builder()
                    .tenantId(row.tenantId())
                    .entityVersion(row.entityVersion())
                    .eventId(row.eventId())
                    .extraHeaders(headers)
                    .build();

            var result = reliablePublisher.publish(row.topic(), key, value, opts);

            int updated = markPublished(row.id(),
                    result.getRecordMetadata().partition(),
                    result.getRecordMetadata().offset());
            if (updated == 0) {
                log.warn("outbox_mark_published_noop id={} topic={} partition={} offset={}",
                        row.id(), row.topic(),
                        result.getRecordMetadata().partition(),
                        result.getRecordMetadata().offset());
            }
            metrics.counter("outbox.record.published", Tags.of("topic", row.topic())).increment();
            span.setStatus(StatusCode.OK);
        } catch (Exception e) {
            int attempts = row.attempts();
            boolean giveUp = attempts >= maxAttempts;
            Duration backoff = computeBackoff(attempts);
            Instant nextAt = clock.instant().plus(backoff);
            String reason = truncate(safeMsg(e), 500);
            String errClass = e.getClass().getSimpleName();

            int updated = markRetryOrFail(row.id(), giveUp, nextAt, reason, errClass);
            if (updated == 0) {
                log.warn("outbox_mark_retry_noop id={} giveUp={} errClass={} msg={}", row.id(), giveUp, errClass, reason);
            }
            metrics.counter(giveUp ? "outbox.record.failed" : "outbox.record.retry",
                    Tags.of("topic", row.topic(), "class", errClass)).increment();

            span.recordException(e);
            span.setStatus(StatusCode.ERROR, reason);
        } finally {
            span.end();
        }
    }

    private int markPublished(long id, int partition, long offset) {
        String sql = """
            UPDATE %s
               SET status = 'PUBLISHED',
                   published_at = now(),
                   last_error = NULL,
                   last_error_class = NULL,
                   updated_at = now()
             WHERE id = ?
            """.formatted(table);
        return jdbc.update(sql, id);
    }

    private int markRetryOrFail(long id, boolean fail, Instant nextAttemptAt, String reason, String errClass) {
        String sql;
        if (fail) {
            sql = """
                UPDATE %s
                   SET status = 'FAILED',
                       next_attempt_at = NULL,
                       last_error = ?,
                       last_error_class = ?,
                       updated_at = now()
                 WHERE id = ?
                """.formatted(table);
            return jdbc.update(sql, reason, errClass, id);
        } else {
            sql = """
                UPDATE %s
                   SET status = 'RETRY',
                       next_attempt_at = ?,
                       last_error = ?,
                       last_error_class = ?,
                       updated_at = now()
                 WHERE id = ?
                """.formatted(table);
            return jdbc.update(sql, nextAttemptAt, reason, errClass, id);
        }
    }

    private Map<String, String> parseHeaders(@Nullable String json) {
        if (!StringUtils.hasText(json)) return Map.of();
        try {
            return objectMapper.readValue(json, MAP_STRING_STRING);
        } catch (Exception e) {
            metrics.counter("outbox.headers.parse_error").increment();
            log.warn("outbox_headers_parse_error msg={}", safeMsg(e));
            return Map.of();
        }
    }

    private static Map<String, String> putIfAbsent(Map<String, String> headers, String key, @Nullable String value) {
        if (!StringUtils.hasText(value)) return headers;
        if (headers != null && value.equals(headers.get(key))) return headers;
        var copy = new java.util.HashMap<>(headers == null ? Map.<String, String>of() : headers);
        copy.putIfAbsent(key, value);
        return copy;
    }

    private Duration computeBackoff(int attempts) {
        long expMillis = (long) (baseBackoff.toMillis() * Math.pow(2, Math.max(0, attempts - 1)));
        long capped = Math.min(expMillis, maxBackoff.toMillis());
        long jitterMs = 50 + jitter.nextInt(200);
        return Duration.ofMillis(capped + jitterMs);
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        if (m == null) return t.getClass().getSimpleName();
        return m.length() > 400 ? m.substring(0, 400) + "..." : m;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private static String hashForLog(String raw) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6);
        } catch (Exception e) {
            return Integer.toHexString(raw.hashCode());
        }
    }

    private String workerId() {
        try {
            String host = InetAddress.getLocalHost().getHostName();
            String pid = ManagementPid.HOLDER.pid();
            return "worker:" + host + ":" + pid;
        } catch (Exception e) {
            return "worker:unknown:" + ManagementPid.HOLDER.pid();
        }
    }

    public record OutboxRow(
            long id,
            String tenantId,
            String topic,
            byte[] keyBytes,
            byte[] valueBytes,
            @Nullable String headersJson,
            @Nullable String eventId,
            @Nullable Long entityVersion,
            int attempts,
            String status,
            Instant nextAttemptAt,
            Instant createdAt
    ) {}

    private static final class ManagementPid {
        private static final ManagementPid HOLDER = new ManagementPid();
        private final String pid;
        private ManagementPid() {
            String jvmName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            String parsed = jvmName;
            int idx = jvmName.indexOf('@');
            if (idx > 0) parsed = jvmName.substring(0, idx);
            this.pid = parsed;
        }
        String pid() { return pid; }
    }

    @Override
    public void close() {
        vthreads.shutdown();
        try {
            if (!vthreads.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                vthreads.shutdownNow();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
