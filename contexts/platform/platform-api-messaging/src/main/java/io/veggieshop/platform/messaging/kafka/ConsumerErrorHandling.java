package io.veggieshop.platform.messaging.kafka;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.AuthorizationException;
import org.apache.kafka.common.errors.InvalidTopicException;
import org.apache.kafka.common.errors.RecordDeserializationException;
import org.apache.kafka.common.errors.RetriableException;
import org.apache.kafka.common.errors.UnsupportedVersionException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.kafka.support.ExponentialBackOffWithMaxRetries;
import org.springframework.messaging.converter.MessageConversionException;
import org.springframework.util.backoff.BackOff;
import org.springframework.util.backoff.BackOffExecution;

/**
 * Centralized, opinionated consumer error handling utilities for Kafka listeners.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Build a {@link DeadLetterPublishingRecoverer} that routes failed records to a quarantine
 *       topic with rich headers (root cause, stack hash, attempt, envelope, and W3C trace context).
 *   <li>Build a {@link DefaultErrorHandler} with exponential backoff + jitter, proper
 *       classification of retryable/non-retryable exceptions, and optional commit on recover.
 *   <li>Provide small helpers for delivery attempt extraction, root cause discovery, and safe
 *       hashing/truncation.
 * </ul>
 *
 * <p>Design notes:
 *
 * <ul>
 *   <li>No wildcard imports (Checkstyle-friendly).
 *   <li>Strict braces for all control structures.
 *   <li>Headers are propagated via {@link Headers} helpers; no PII is logged.
 * </ul>
 */
public final class ConsumerErrorHandling {

  private ConsumerErrorHandling() {
    // utility
  }

  /**
   * Builds a {@link DeadLetterPublishingRecoverer} that publishes to {@code originalTopic +
   * quarantineSuffix} on the same partition.
   *
   * <p>The recoverer also mirrors safe headers, attaches an envelope (tenant, trace, schema
   * fingerprint, entity version), adds error diagnostics, and propagates W3C trace context.
   *
   * @param kafkaTemplate the template used to publish to the quarantine topic
   * @param quarantineSuffix suffix appended to the original topic name
   * @return configured recoverer
   */
  public static DeadLetterPublishingRecoverer buildQuarantineRecoverer(
      KafkaTemplate<Object, Object> kafkaTemplate, String quarantineSuffix) {

    DeadLetterPublishingRecoverer r =
        new DeadLetterPublishingRecoverer(
            kafkaTemplate,
            (rec, ex) -> new TopicPartition(rec.topic() + quarantineSuffix, rec.partition()));

    r.setHeadersFunction(
        (record, ex) -> {
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
              Headers.getAsString(record.headers(), Headers.Keys.TENANT_ID).orElse(null),
              Headers.getAsString(record.headers(), Headers.Keys.TRACE_ID).orElse(null),
              Headers.getAsString(record.headers(), Headers.Keys.SCHEMA_FINGERPRINT).orElse(null),
              Headers.getAsLong(record.headers(), Headers.Keys.ENTITY_VERSION).orElse(null));

          Headers.propagateW3cTraceContext(record.headers(), h);
          return h;
        });

    return r;
  }

  /**
   * Builds a {@link DefaultErrorHandler} with exponential backoff + jitter and curated retryability
   * rules. Non-retryable classes include deserialization and protocol/authorization errors; {@link
   * RetriableException} is retryable.
   *
   * @param recoverer recoverer to handle exhausted retries
   * @param maxRetries maximum backoff steps (retries)
   * @param initialMs initial backoff in milliseconds
   * @param multiplier exponential multiplier
   * @param maxMs maximum backoff in milliseconds
   * @param jitterFrac 0..0.9 random jitter fraction applied to the backoff
   * @param commitRecovered whether to commit offsets upon successful recovery
   * @param retryListener optional retry listener hook
   * @return configured error handler
   */
  public static DefaultErrorHandler buildDefaultErrorHandler(
      DeadLetterPublishingRecoverer recoverer,
      int maxRetries,
      long initialMs,
      double multiplier,
      long maxMs,
      double jitterFrac,
      boolean commitRecovered,
      RetryListener retryListener) {

    ExponentialBackOffWithMaxRetries base = new ExponentialBackOffWithMaxRetries(maxRetries);
    base.setInitialInterval(initialMs);
    base.setMultiplier(multiplier);
    base.setMaxInterval(maxMs);

    DefaultErrorHandler handler =
        new DefaultErrorHandler(recoverer, new JitteringBackOff(base, jitterFrac));

    handler.addNotRetryableExceptions(
        org.springframework.kafka.support.serializer.DeserializationException.class,
        RecordDeserializationException.class,
        MessageConversionException.class,
        InvalidTopicException.class,
        AuthorizationException.class,
        UnsupportedVersionException.class);

    handler.addRetryableExceptions(RetriableException.class);
    handler.setCommitRecovered(commitRecovered);

    if (retryListener != null) {
      handler.setRetryListeners(retryListener);
    }
    return handler;
  }

  /**
   * Extracts Kafka delivery attempt (Spring header {@code kafka_deliveryAttempt}) when available.
   *
   * @param record consumer record
   * @return attempt number if present and parseable, otherwise empty
   */
  public static Optional<Integer> deliveryAttempt(ConsumerRecord<?, ?> record) {
    if (record == null || record.headers() == null) {
      return Optional.empty();
    }
    var hdr = record.headers().lastHeader("kafka_deliveryAttempt");
    if (hdr == null || hdr.value() == null) {
      return Optional.empty();
    }
    try {
      String v = new String(hdr.value(), StandardCharsets.UTF_8).trim();
      return Optional.of(Integer.parseInt(v));
    } catch (Exception ignore) {
      return Optional.empty();
    }
  }

  /**
   * Walks {@link Throwable#getCause()} chain to return the root cause.
   *
   * @param ex throwable
   * @return deepest cause (or {@code ex} if none)
   */
  public static Throwable rootCause(Throwable ex) {
    Throwable t = ex;
    while (t.getCause() != null && t.getCause() != t) {
      t = t.getCause();
    }
    return t;
  }

  /**
   * Truncates a string to {@code max} characters with an ellipsis when needed.
   *
   * @param s input
   * @param max maximum length
   * @return truncated string
   */
  public static String safeTruncate(String s, int max) {
    if (s == null || s.length() <= max) {
      return s;
    }
    int end = Math.max(0, max - 3);
    return s.substring(0, end) + "...";
  }

  /**
   * Renders a bounded stack trace string for hashing/diagnostics.
   *
   * @param t throwable
   * @return stack trace text (capped at ~8KB)
   */
  public static String stackTraceAsString(Throwable t) {
    StringBuilder sb = new StringBuilder(1024).append(t.getClass().getName()).append('\n');
    for (StackTraceElement el : t.getStackTrace()) {
      sb.append("  at ").append(el).append('\n');
      if (sb.length() > 8192) {
        break;
      }
    }
    return sb.toString();
  }

  /**
   * Computes a SHA-256 hex digest and returns the first 32 chars.
   *
   * @param in input text
   * @return 32-char hex digest or {@code "na"} on error
   */
  public static String sha256Hex(String in) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] out = md.digest(in.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(out.length * 2);
      for (byte b : out) {
        sb.append(String.format(Locale.ROOT, "%02x", b));
      }
      int end = Math.min(sb.length(), 32);
      return sb.substring(0, end);
    } catch (Exception e) {
      return "na";
    }
  }

  /**
   * BackOff wrapper that applies symmetric random jitter to each computed backoff interval. Jitter
   * range = {@code base * ±jitter}.
   */
  public static final class JitteringBackOff implements BackOff {
    private final BackOff delegate;
    private final double jitter;

    /**
     * Creates a jittering backoff.
     *
     * @param delegate base backoff implementation
     * @param jitter fraction in [0..0.9] applied as ±random noise
     */
    public JitteringBackOff(BackOff delegate, double jitter) {
      this.delegate = delegate;
      this.jitter = Math.max(0.0, Math.min(jitter, 0.9));
    }

    @Override
    public BackOffExecution start() {
      BackOffExecution exec = delegate.start();
      return new BackOffExecution() {
        @Override
        public long nextBackOff() {
          long base = exec.nextBackOff();
          if (base == STOP) {
            return STOP;
          }
          double delta = (Math.random() * 2 - 1) * jitter;
          long jittered = Math.round(base + base * delta);
          return Math.max(0L, jittered);
        }
      };
    }
  }
}
