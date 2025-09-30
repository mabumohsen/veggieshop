package io.veggieshop.platform.starter.messaging.autoconfig;

import io.veggieshop.platform.messaging.outbox.OutboxPublisher;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ScheduledFuture;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * Auto-configuration for a lightweight scheduler that periodically drains the outbox table. It uses
 * {@link TaskScheduler#scheduleWithFixedDelay(Runnable, Instant, Duration)} with an initial delay
 * and fixed delay between runs, and supports a short "burst" to catch up when there is backlog.
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "veggieshop.outbox.scheduler",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class OutboxSchedulerConfiguration {

  /**
   * Small single-threaded scheduler dedicated to outbox draining.
   *
   * @return a configured {@link TaskScheduler}
   */
  @Bean
  TaskScheduler outboxTaskScheduler() {
    ThreadPoolTaskScheduler s = new ThreadPoolTaskScheduler();
    s.setPoolSize(1);
    s.setThreadNamePrefix("outbox-drain-");
    s.initialize();
    return s;
  }

  /**
   * Schedules the outbox-drain runnable with a fixed delay. Performs a bounded "burst" of drain
   * attempts per tick, then sleeps briefly when idle to reduce churn.
   *
   * @param scheduler the task scheduler
   * @param outbox the outbox publisher abstraction
   * @param p the outbox properties (including scheduler tuning)
   * @return a {@link ScheduledFuture} representing the scheduled task
   */
  @Bean
  ScheduledFuture<?> outboxDrainLoop(
      TaskScheduler scheduler, OutboxPublisher outbox, VeggieOutboxProperties p) {

    Duration initial = p.getScheduler().getInitialDelay();
    Duration interval = p.getScheduler().getInterval();
    int burst = p.getScheduler().getBurstBatches();
    Duration maxBurst = p.getScheduler().getMaxBurstDuration();
    Duration idleSleep = p.getScheduler().getIdleSleep();

    // scheduleWithFixedDelay(Runnable, Instant startTime, Duration delay)
    return scheduler.scheduleWithFixedDelay(
        () -> {
          long start = System.nanoTime();
          int done = 0;
          while (done < burst && (System.nanoTime() - start) < maxBurst.toNanos()) {
            try {
              outbox.drainOnce();
              done++;
            } catch (Exception e) {
              // Optionally add metrics/logs here if needed
              break;
            }
          }
          if (done == 0) {
            // No backlog? Sleep a bit to reduce pressure.
            try {
              Thread.sleep(idleSleep.toMillis());
            } catch (InterruptedException ignored) {
              Thread.currentThread().interrupt();
            }
          }
        },
        Instant.now().plus(initial),
        interval);
  }
}
