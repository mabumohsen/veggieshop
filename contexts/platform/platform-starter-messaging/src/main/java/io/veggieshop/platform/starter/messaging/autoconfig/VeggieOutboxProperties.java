package io.veggieshop.platform.starter.messaging.autoconfig;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the Outbox pattern integration (table, batching, backoff, etc.).
 * Nested {@code scheduler} allows tuning the internal scheduler used by this starter.
 */
@ConfigurationProperties(prefix = "veggieshop.outbox")
public class VeggieOutboxProperties {

  private String table = "platform_outbox";
  private int batchSize = 200;
  private int parallelism = 8;
  private int maxAttempts = 20;
  private Duration backoffBase = Duration.ofSeconds(1);
  private Duration backoffMax = Duration.ofMinutes(5);

  /** Scheduler control is provided by the starter only. */
  private final Scheduler scheduler = new Scheduler();

  /** Outbox table name. */
  public String getTable() {
    return table;
  }

  public void setTable(String table) {
    this.table = table;
  }

  /** Number of records per fetch/dispatch batch. */
  public int getBatchSize() {
    return batchSize;
  }

  public void setBatchSize(int batchSize) {
    this.batchSize = batchSize;
  }

  /** Degree of parallel processing for dispatching. */
  public int getParallelism() {
    return parallelism;
  }

  public void setParallelism(int parallelism) {
    this.parallelism = parallelism;
  }

  /** Maximum retry attempts per outbox record. */
  public int getMaxAttempts() {
    return maxAttempts;
  }

  public void setMaxAttempts(int maxAttempts) {
    this.maxAttempts = maxAttempts;
  }

  /** Base (initial) backoff duration. */
  public Duration getBackoffBase() {
    return backoffBase;
  }

  public void setBackoffBase(Duration backoffBase) {
    this.backoffBase = backoffBase;
  }

  /** Cap for exponential backoff duration. */
  public Duration getBackoffMax() {
    return backoffMax;
  }

  public void setBackoffMax(Duration backoffMax) {
    this.backoffMax = backoffMax;
  }

  /**
   * Exposes the nested scheduler bean for property binding. Returning the live instance is required
   * for Spring Boot binder to populate nested fields.
   */
  @SuppressFBWarnings("EI_EXPOSE_REP")
  public Scheduler getScheduler() {
    return scheduler;
  }

  /** Scheduler sub-properties for the internal outbox drain loop. */
  public static class Scheduler {
    private boolean enabled = true;

    /** Initial delay before first drain run. */
    private Duration initialDelay = Duration.ofSeconds(1);

    /** Fixed delay between successive drain runs. */
    private Duration interval = Duration.ofMillis(250);

    /** Max batches per tick when backlog exists. */
    private int burstBatches = 3;

    /** Time budget for a single burst window. */
    private Duration maxBurstDuration = Duration.ofSeconds(2);

    /** Sleep time when no work was done. */
    private Duration idleSleep = Duration.ofSeconds(1);

    /** Whether the scheduler is enabled. */
    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    /** Initial delay before the first run. */
    public Duration getInitialDelay() {
      return initialDelay;
    }

    public void setInitialDelay(Duration initialDelay) {
      this.initialDelay = initialDelay;
    }

    /** Fixed delay between runs. */
    public Duration getInterval() {
      return interval;
    }

    public void setInterval(Duration interval) {
      this.interval = interval;
    }

    /** Max number of batches to execute per tick. */
    public int getBurstBatches() {
      return burstBatches;
    }

    public void setBurstBatches(int burstBatches) {
      this.burstBatches = burstBatches;
    }

    /** Maximum time budget for a single burst. */
    public Duration getMaxBurstDuration() {
      return maxBurstDuration;
    }

    public void setMaxBurstDuration(Duration maxBurstDuration) {
      this.maxBurstDuration = maxBurstDuration;
    }

    /** Idle sleep duration when no work is available. */
    public Duration getIdleSleep() {
      return idleSleep;
    }

    public void setIdleSleep(Duration idleSleep) {
      this.idleSleep = idleSleep;
    }
  }
}
