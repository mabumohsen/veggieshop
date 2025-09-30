package io.veggieshop.platform.starter.messaging.autoconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.veggieshop.platform.messaging.dedupe.DedupeService;
import io.veggieshop.platform.messaging.kafka.ConsumerErrorHandling;
import io.veggieshop.platform.messaging.kafka.ReliablePublisher;
import io.veggieshop.platform.messaging.outbox.OutboxPublisher;
import jakarta.annotation.Nullable;
import java.time.Clock;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.RetryListener;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Auto-configuration that wires messaging components: quarantine/DLQ recoverer, consumer error
 * handler, reliable publisher, outbox publisher, and dedupe service.
 */
@AutoConfiguration
@EnableConfigurationProperties({
  VeggieKafkaErrorProperties.class,
  VeggiePublisherProperties.class,
  VeggieOutboxProperties.class,
  VeggieDedupeProperties.class
})
public class VeggieShopMessagingAutoConfiguration {

  private static final Logger log =
      LoggerFactory.getLogger(VeggieShopMessagingAutoConfiguration.class);

  /** Builds a recoverer that routes poisoned records to a quarantine topic (DLQ). */
  @Bean
  @ConditionalOnMissingBean
  DeadLetterPublishingRecoverer quarantineRecoverer(
      KafkaTemplate<Object, Object> kafkaTemplate, VeggieKafkaErrorProperties p) {
    return ConsumerErrorHandling.buildQuarantineRecoverer(kafkaTemplate, p.getQuarantineSuffix());
  }

  /** Configures the default consumer error handler with backoff and jitter based on properties. */
  @Bean
  @ConditionalOnMissingBean
  DefaultErrorHandler kafkaConsumerErrorHandler(
      DeadLetterPublishingRecoverer recoverer, VeggieKafkaErrorProperties p) {
    RetryListener rl =
        new RetryListener() {
          @Override
          public void failedDelivery(ConsumerRecord<?, ?> rec, Exception ex, int attempt) {
            log.warn(
                "consumer_retry_failed topic={} partition={} offset={} attempt={} err={} root={}",
                rec.topic(),
                rec.partition(),
                rec.offset(),
                attempt,
                ex.getClass().getName(),
                ConsumerErrorHandling.rootCause(ex).getClass().getName());
          }
        };
    return ConsumerErrorHandling.buildDefaultErrorHandler(
        recoverer,
        p.getMaxRetries(),
        p.getInitialIntervalMs(),
        p.getMultiplier(),
        p.getMaxIntervalMs(),
        p.getJitterFraction(),
        p.isCommitRecovered(),
        rl);
  }

  /** Creates a ReliablePublisher with metrics and OpenTelemetry tracer. */
  @Bean
  @ConditionalOnMissingBean
  ReliablePublisher reliablePublisher(
      KafkaTemplate<Object, Object> kafkaTemplate,
      MeterRegistry meterRegistry,
      VeggiePublisherProperties p) {
    return new ReliablePublisher(
        kafkaTemplate,
        meterRegistry,
        GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.kafka"),
        Clock.systemUTC(),
        p.getMaxAttempts(),
        p.getInitialBackoff(),
        p.getBackoffMultiplier(),
        p.getMaxBackoff(),
        p.getJitterRatio(),
        p.getSendTimeout());
  }

  /** Creates the OutboxPublisher backed by JDBC and the ReliablePublisher. */
  @Bean(destroyMethod = "close")
  @ConditionalOnMissingBean
  OutboxPublisher outboxPublisher(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      ReliablePublisher reliablePublisher,
      ObjectProvider<ObjectMapper> omProvider,
      MeterRegistry meterRegistry,
      ObjectProvider<Clock> clockProvider,
      VeggieOutboxProperties p) {

    ObjectMapper objectMapper = omProvider.getIfAvailable(ObjectMapper::new);
    Clock clock = clockProvider.getIfAvailable(Clock::systemUTC);

    return new OutboxPublisher(
        jdbc,
        tx,
        reliablePublisher,
        objectMapper,
        meterRegistry,
        clock,
        p.getTable(),
        p.getBatchSize(),
        p.getParallelism(),
        p.getMaxAttempts(),
        p.getBackoffBase(),
        p.getBackoffMax());
  }

  /** Provides a DedupeService using JDBC and optional Redis for fast path. */
  @Bean
  @ConditionalOnMissingBean
  DedupeService dedupeService(
      JdbcTemplate jdbc,
      ObjectProvider<StringRedisTemplate> redisProvider,
      MeterRegistry metrics,
      VeggieDedupeProperties p) {
    @Nullable StringRedisTemplate redis = redisProvider.getIfAvailable();
    return new DedupeService(
        jdbc,
        redis,
        metrics,
        p.getTtl(),
        p.getMinAcceptedVersion(),
        p.getReplayWindow(),
        p.getMaxFutureSkew());
  }
}
