package io.veggieshop.platform.messaging.kafka;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.*;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.kafka.support.ExponentialBackOffWithMaxRetries;
import org.springframework.messaging.converter.MessageConversionException;
import org.springframework.util.backoff.BackOff;
import org.springframework.util.backoff.BackOffExecution;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import static io.veggieshop.platform.messaging.kafka.Headers.*;

public final class ConsumerErrorHandling {
    private ConsumerErrorHandling() {
    }

    public static DeadLetterPublishingRecoverer buildQuarantineRecoverer(
            KafkaTemplate<Object, Object> kafkaTemplate, String quarantineSuffix) {

        DeadLetterPublishingRecoverer r = new DeadLetterPublishingRecoverer(
                kafkaTemplate, (rec, ex) -> new TopicPartition(rec.topic() + quarantineSuffix, rec.partition()));

        r.setHeadersFunction((record, ex) -> {
            var h = new org.apache.kafka.common.header.internals.RecordHeaders();
            Headers.copy(record.headers(), h, Headers.Keys::isSafeToPropagate);

            String exceptionClass = ex.getClass().getName();
            String rootClass = rootCause(ex).getClass().getName();
            String msg = safeTruncate(Optional.ofNullable(ex.getMessage()).orElse(rootClass), 512);
            String stackHash = sha256Hex(stackTraceAsString(ex));
            int attempt = deliveryAttempt(record).orElse(1);

            Headers.put(h, "x-error-class", exceptionClass);
            Headers.put(h, "x-error-root-class", rootClass);
            Headers.put(h, "x-error-message", msg);
            Headers.put(h, "x-error-stack-hash", stackHash);
            Headers.putInt(h, "x-retry-attempt", attempt);
            Headers.putInstant(h, "x-quarantined-at", Instant.now());

            Headers.attachEnvelope(
                    h,
                    Headers.getAsString(record.headers(), Keys.TENANT_ID).orElse(null),
                    Headers.getAsString(record.headers(), Keys.TRACE_ID).orElse(null),
                    Headers.getAsString(record.headers(), Keys.SCHEMA_FINGERPRINT).orElse(null),
                    Headers.getAsLong(record.headers(), Keys.ENTITY_VERSION).orElse(null)
            );
            Headers.propagateW3CTraceContext(record.headers(), h);
            return h;
        });

        return r;
    }

    public static DefaultErrorHandler buildDefaultErrorHandler(
            DeadLetterPublishingRecoverer recoverer,
            int maxRetries, long initialMs, double multiplier, long maxMs, double jitterFrac,
            boolean commitRecovered, RetryListener retryListener) {

        ExponentialBackOffWithMaxRetries base = new ExponentialBackOffWithMaxRetries(maxRetries);
        base.setInitialInterval(initialMs);
        base.setMultiplier(multiplier);
        base.setMaxInterval(maxMs);

        DefaultErrorHandler h = new DefaultErrorHandler(recoverer, new JitteringBackOff(base, jitterFrac));
        h.addNotRetryableExceptions(
                org.springframework.kafka.support.serializer.DeserializationException.class,
                RecordDeserializationException.class,
                MessageConversionException.class,
                InvalidTopicException.class, AuthorizationException.class, UnsupportedVersionException.class
        );
        h.addRetryableExceptions(RetriableException.class);
        h.setCommitRecovered(commitRecovered);
        if (retryListener != null) h.setRetryListeners(retryListener);
        return h;
    }

    public static Optional<Integer> deliveryAttempt(ConsumerRecord<?, ?> record) {
        if (record == null || record.headers() == null) return Optional.empty();
        var h = record.headers().lastHeader("kafka_deliveryAttempt");
        if (h == null || h.value() == null) return Optional.empty();
        try {
            return Optional.of(Integer.parseInt(new String(h.value(), StandardCharsets.UTF_8).trim()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static Throwable rootCause(Throwable ex) {
        var t = ex;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        return t;
    }

    public static String safeTruncate(String s, int max) {
        if (s == null || s.length() <= max) return s;
        return s.substring(0, Math.max(0, max - 3)) + "...";
    }

    public static String stackTraceAsString(Throwable t) {
        var sb = new StringBuilder(1024).append(t.getClass().getName()).append('\n');
        for (var el : t.getStackTrace()) {
            sb.append("  at ").append(el).append('\n');
            if (sb.length() > 8192) break;
        }
        return sb.toString();
    }

    public static String sha256Hex(String in) {
        try {
            var md = MessageDigest.getInstance("SHA-256");
            var out = md.digest(in.getBytes(StandardCharsets.UTF_8));
            var sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format(Locale.ROOT, "%02x", b));
            return sb.substring(0, Math.min(sb.length(), 32));
        } catch (Exception e) {
            return "na";
        }
    }

    public static final class JitteringBackOff implements BackOff {
        private final BackOff delegate;
        private final double jitter;

        public JitteringBackOff(BackOff delegate, double jitter) {
            this.delegate = delegate;
            this.jitter = Math.max(0.0, Math.min(jitter, 0.9));
        }

        @Override
        public BackOffExecution start() {
            var exec = delegate.start();
            return new BackOffExecution() {
                @Override
                public long nextBackOff() {
                    long base = exec.nextBackOff();
                    if (base == STOP) return STOP;
                    double delta = (Math.random() * 2 - 1) * jitter;
                    return Math.max(0L, Math.round(base + base * delta));
                }
            };
        }
    }
}
