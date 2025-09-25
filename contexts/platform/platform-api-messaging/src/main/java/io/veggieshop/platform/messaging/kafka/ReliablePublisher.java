package io.veggieshop.platform.messaging.kafka;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapSetter;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.errors.RetriableException;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class ReliablePublisher {

    private static final Logger log = LoggerFactory.getLogger(ReliablePublisher.class);

    // مِحقَن W3C tracecontext للـ Kafka headers عبر OpenTelemetry
    private static final TextMapSetter<org.apache.kafka.common.header.Headers> KAFKA_HEADER_SETTER =
            (carrier, key, value) -> {
                if (carrier == null || key == null || value == null) return;
                carrier.remove(key);
                carrier.add(key, value.getBytes(StandardCharsets.UTF_8));
            };

    private final KafkaTemplate<Object, Object> kafkaTemplate;
    private final MeterRegistry meterRegistry;
    private final Tracer tracer;
    private final Clock clock;

    private final int maxAttempts;
    private final Duration initialBackoff;
    private final double backoffMultiplier;
    private final Duration maxBackoff;
    private final double jitterRatio;
    private final Duration sendTimeout;

    public ReliablePublisher(KafkaTemplate<Object, Object> kafkaTemplate, MeterRegistry meterRegistry) {
        this(kafkaTemplate, meterRegistry,
                GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.kafka"),
                Clock.systemUTC(),
                3,                        // maxAttempts
                Duration.ofMillis(250),   // initialBackoff
                2.0,                      // backoffMultiplier
                Duration.ofSeconds(5),    // maxBackoff
                0.20,                     // ±20% jitter
                Duration.ofSeconds(10));  // sendTimeout
    }

    public ReliablePublisher(KafkaTemplate<Object, Object> kafkaTemplate,
                             MeterRegistry meterRegistry,
                             Tracer tracer,
                             Clock clock,
                             int maxAttempts,
                             Duration initialBackoff,
                             double backoffMultiplier,
                             Duration maxBackoff,
                             double jitterRatio,
                             Duration sendTimeout) {
        this.kafkaTemplate = Objects.requireNonNull(kafkaTemplate, "kafkaTemplate");
        this.meterRegistry = Objects.requireNonNull(meterRegistry, "meterRegistry");
        this.tracer = Objects.requireNonNull(tracer, "tracer");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxAttempts = Math.max(1, maxAttempts);
        this.initialBackoff = Objects.requireNonNull(initialBackoff, "initialBackoff");
        this.backoffMultiplier = Math.max(1.0, backoffMultiplier);
        this.maxBackoff = Objects.requireNonNull(maxBackoff, "maxBackoff");
        this.jitterRatio = Math.max(0.0, Math.min(jitterRatio, 0.9));
        this.sendTimeout = Objects.requireNonNull(sendTimeout, "sendTimeout");
    }

    public SendResult<Object, Object> publish(String topic, Object key, Object value, PublisherOptions options) {
        try {
            return publishInternal(topic, key, value, options, true)
                    .get(sendTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            throw new KafkaPublishException("Failed to publish after retries. topic=" + topic, e);
        }
    }

    public CompletableFuture<SendResult<Object, Object>> publishAsync(String topic,
                                                                      Object key,
                                                                      Object value,
                                                                      PublisherOptions options) {
        return publishInternal(topic, key, value, options, false);
    }

    private CompletableFuture<SendResult<Object, Object>> publishInternal(String topic,
                                                                          Object key,
                                                                          Object value,
                                                                          PublisherOptions options,
                                                                          boolean logBlocking) {
        Objects.requireNonNull(topic, "topic");
        Objects.requireNonNull(options, "options");

        RecordHeaders headers = new RecordHeaders();

        // Envelope (tenant/trace/schema/version)
        String currentTraceId = currentTraceId();
        Headers.attachEnvelope(
                headers,
                coalesce(options.tenantId(), Headers.getAsString(options.extraHeaders(), Headers.Keys.TENANT_ID).orElse(null)),
                coalesce(currentTraceId, Headers.getAsString(options.extraHeaders(), Headers.Keys.TRACE_ID).orElse(null)),
                options.schemaFingerprint(),
                options.entityVersion()
        );

        // حقن traceparent/tracestate من السياق الحالي (OTel)
        GlobalOpenTelemetry.getPropagators()
                .getTextMapPropagator()
                .inject(Context.current(), headers, KAFKA_HEADER_SETTER);

        // event-id ثابت لتفعيل idempotency على المستهلكين
        String eventId = coalesce(options.eventId(), UUID.randomUUID().toString());
        Headers.put(headers, "x-event-id", eventId);

        if (options.aggregateId() != null) Headers.put(headers, "x-aggregate-id", options.aggregateId());
        if (options.family() != null) Headers.put(headers, "x-event-family", options.family());

        // هيدرز إضافية آمنة
        Headers.copy(options.extraHeaders(), headers, Headers.Keys::isSafeToPropagate);

        long ts = options.timestamp() != null ? options.timestamp().toEpochMilli() : clock.millis();

        ProducerRecord<Object, Object> record = options.partition() == null
                ? new ProducerRecord<>(topic, null, ts, key, value, headers)
                : new ProducerRecord<>(topic, options.partition(), ts, key, value, headers);

        // Tags ثابتة
        List<Tag> tagList = List.of(
                Tag.of("topic", topic),
                Tag.of("tenant", Headers.getAsString(headers, Headers.Keys.TENANT_ID).orElse("na")),
                Tag.of("family", options.family() != null ? options.family() : "na")
        );
        Tags tags = Tags.of(tagList);

        Timer timer = Timer.builder("messaging.kafka.publish.latency")
                .description("Kafka publish latency (successful sends only)")
                .tags(tags)
                .register(meterRegistry);

        CompletableFuture<SendResult<Object, Object>> terminal = new CompletableFuture<>();
        int attempt = 0;

        while (true) {
            attempt++;
            Headers.putInt(headers, "x-producer-attempt", attempt);

            Span span = tracer.spanBuilder("kafka.publish")
                    .setSpanKind(SpanKind.PRODUCER)
                    .startSpan();

            span.setAttribute("messaging.system", "kafka");
            span.setAttribute("messaging.destination.name", topic);
            span.setAttribute("messaging.destination.kind", "topic");
            span.setAttribute("messaging.kafka.message.key_set", key != null);
            span.setAttribute("messaging.kafka.partition", record.partition() == null ? -1 : record.partition());
            span.setAttribute("veggieshop.tenant_id", Headers.getAsString(headers, Headers.Keys.TENANT_ID).orElse("na"));
            span.setAttribute("veggieshop.event_id", eventId);
            span.setAttribute("veggieshop.publish.attempt", attempt);

            long startNanos = System.nanoTime();
            try {
                // Spring Kafka 3.3+ يُرجِع CompletableFuture مباشرة
                CompletableFuture<SendResult<Object, Object>> cf = kafkaTemplate.send(record);
                SendResult<Object, Object> result = cf.get(sendTimeout.toMillis(), TimeUnit.MILLISECONDS);

                long dur = System.nanoTime() - startNanos;
                timer.record(dur, TimeUnit.NANOSECONDS);
                span.setStatus(StatusCode.OK);
                span.end();

                meterRegistry.counter("messaging.kafka.publish.success", tags).increment();

                if (log.isDebugEnabled()) {
                    log.debug("kafka_publish_ok topic={} partition={} offset={} keyPresent={} tenant={} eventId={} attempt={}",
                            topic,
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset(),
                            key != null,
                            Headers.getAsString(headers, Headers.Keys.TENANT_ID).orElse("na"),
                            eventId,
                            attempt
                    );
                }

                terminal.complete(result);
                break;

            } catch (Exception ex) {
                Throwable root = rootCause(ex);
                span.recordException(root);
                span.setStatus(StatusCode.ERROR, safeMessage(root));
                span.end();

                boolean retryable = isRetryable(root);
                boolean hasMore = attempt < maxAttempts;

                meterRegistry.counter("messaging.kafka.publish.failure",
                        Tags.of("topic", topic, "retryable", Boolean.toString(retryable))).increment();

                if (!retryable || !hasMore) {
                    log.warn("kafka_publish_fail topic={} keyPresent={} tenant={} eventId={} attempt={} retryable={} errorClass={}",
                            topic,
                            key != null,
                            Headers.getAsString(headers, Headers.Keys.TENANT_ID).orElse("na"),
                            eventId,
                            attempt,
                            retryable,
                            root.getClass().getName()
                    );
                    terminal.completeExceptionally(root);
                    break;
                }

                Duration sleep = nextBackoff(attempt);
                if (logBlocking && log.isDebugEnabled()) {
                    log.debug("kafka_publish_retry topic={} attempt={} backoffMs={}", topic, attempt, sleep.toMillis());
                }
                sleepQuietly(sleep);
            }
        }

        return terminal;
    }

    // ------------ Helpers ------------

    private String currentTraceId() {
        Span span = Span.current();
        if (span == null) return null;
        String traceId = span.getSpanContext().getTraceId();
        return (traceId == null || traceId.isEmpty() || "00000000000000000000000000000000".equals(traceId)) ? null : traceId;
    }

    private boolean isRetryable(Throwable t) {
        if (t instanceof RetriableException) return true;
        if (t instanceof KafkaException) return true;
        return false;
    }

    private Duration nextBackoff(int attempt) {
        if (attempt <= 1) return withJitter(initialBackoff);
        double pow = Math.pow(backoffMultiplier, Math.max(0, attempt - 1));
        long millis = (long) Math.min(maxBackoff.toMillis(), initialBackoff.toMillis() * pow);
        return withJitter(Duration.ofMillis(millis));
    }

    private Duration withJitter(Duration base) {
        if (jitterRatio <= 0) return base;
        double delta = (Math.random() * 2 - 1) * jitterRatio;
        long jittered = Math.max(0L, Math.round(base.toMillis() * (1.0 + delta)));
        return Duration.ofMillis(jittered);
    }

    private static void sleepQuietly(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private static Throwable rootCause(Throwable ex) {
        Throwable t = ex;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        return t;
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        if (m == null) return t.getClass().getSimpleName();
        return m.length() > 256 ? m.substring(0, 253) + "..." : m;
    }

    private static <T> T coalesce(T a, T b) {
        return a != null ? a : b;
    }

    // ------------ Options ------------

    public record PublisherOptions(
            String tenantId,
            String eventId,
            String family,
            String aggregateId,
            String schemaFingerprint,
            Long entityVersion,
            Integer partition,
            Instant timestamp,
            org.apache.kafka.common.header.Headers extraHeaders
    ) {
        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String tenantId;
            private String eventId;
            private String family;
            private String aggregateId;
            private String schemaFingerprint;
            private Long entityVersion;
            private Integer partition;
            private Instant timestamp;
            private org.apache.kafka.common.header.Headers extraHeaders;

            public Builder tenantId(String v) {
                this.tenantId = v;
                return this;
            }

            public Builder eventId(String v) {
                this.eventId = v;
                return this;
            }

            public Builder family(String v) {
                this.family = v;
                return this;
            }

            public Builder aggregateId(String v) {
                this.aggregateId = v;
                return this;
            }

            public Builder schemaFingerprint(String v) {
                this.schemaFingerprint = v;
                return this;
            }

            public Builder entityVersion(Long v) {
                this.entityVersion = v;
                return this;
            }

            public Builder partition(Integer v) {
                this.partition = v;
                return this;
            }

            public Builder timestamp(Instant v) {
                this.timestamp = v;
                return this;
            }

            public Builder extraHeaders(Map<String, String> map) {
                RecordHeaders h = new RecordHeaders();
                if (map != null) map.forEach((k, v2) -> Headers.put(h, k, v2));
                this.extraHeaders = h;
                return this;
            }

            public Builder extraHeaders(org.apache.kafka.common.header.Headers h) {
                this.extraHeaders = h;
                return this;
            }

            public PublisherOptions build() {
                return new PublisherOptions(tenantId, eventId, family, aggregateId, schemaFingerprint,
                        entityVersion, partition, timestamp, extraHeaders != null ? extraHeaders : new RecordHeaders());
            }
        }
    }

    public static final class KafkaPublishException extends RuntimeException {
        public KafkaPublishException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
