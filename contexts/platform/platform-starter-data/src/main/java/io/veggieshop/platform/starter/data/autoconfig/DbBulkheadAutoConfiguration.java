package io.veggieshop.platform.starter.data.autoconfig;

import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.Nullable;
import java.io.Serial;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * Auto-configuration that provides a "DB bulkhead" to limit concurrent DB-bound work, with optional
 * AspectJ advice to apply it declaratively via {@link DbLimited}.
 *
 * <p>Enabled via {@code veggieshop.db.bulkhead.enabled=true} (defaults to true). Designed to
 * complement HikariCP limits by bounding application concurrency before DB saturation.
 */
@AutoConfiguration
@AutoConfigureAfter({DataSourceAutoConfiguration.class})
@EnableConfigurationProperties(DbBulkheadAutoConfiguration.DbBulkheadProperties.class)
@ConditionalOnClass({DataSource.class})
@ConditionalOnProperty(
    prefix = "veggieshop.db.bulkhead",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class DbBulkheadAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(DbBulkheadAutoConfiguration.class);

  // ------------------------- Bean: DbBulkhead -------------------------

  /**
   * Creates the {@link DbBulkhead} with a computed or explicit concurrency limit and optional
   * Micrometer metrics.
   */
  @Bean
  @ConditionalOnMissingBean
  public DbBulkhead dbBulkhead(
      DbBulkheadProperties props,
      ObjectProvider<DataSource> dataSource,
      ObjectProvider<MeterRegistry> registry) {

    int computedLimit = computeLimit(props, dataSource.getIfAvailable());
    DbBulkhead bulkhead =
        new DbBulkhead(
            computedLimit,
            props.isFair(),
            props.getAcquireTimeout(),
            props.getPolicy(),
            registry.getIfAvailable());

    log.info(
        "DB Bulkhead initialized: limit={}, fair={}, acquireTimeout={}, policy={}",
        computedLimit,
        props.isFair(),
        props.getAcquireTimeout(),
        props.getPolicy());

    return bulkhead;
  }

  private static int computeLimit(DbBulkheadProperties props, @Nullable DataSource ds) {
    if (!props.isEnabled()) {
      return Integer.MAX_VALUE; // no effective bound
    }
    if (props.getMaxConcurrent() > 0) {
      return props.getMaxConcurrent();
    }
    // Derive from Hikari maximumPoolSize when available
    int base = 32; // reasonable default
    if (ds instanceof HikariDataSource hikari) {
      base = Math.max(1, hikari.getMaximumPoolSize());
    }
    double mult = Math.max(1.0, props.getHeadroomMultiplier());
    long candidate = Math.round(Math.floor(base * mult));
    int bounded = (int) Math.max(props.getMinBound(), Math.min(props.getMaxBound(), candidate));
    return Math.max(1, bounded);
  }

  // ------------------------- Aspect (optional) -------------------------

  /**
   * Declares the aspect that applies the bulkhead to methods annotated with {@link DbLimited} (or
   * within annotated types).
   */
  @Bean
  @ConditionalOnClass(name = "org.aspectj.lang.JoinPoint")
  @ConditionalOnMissingBean
  @ConditionalOnProperty(
      prefix = "veggieshop.db.bulkhead",
      name = "aspect-enabled",
      havingValue = "true",
      matchIfMissing = true)
  public DbBulkheadAspect dbBulkheadAspect(DbBulkhead bulkhead) {
    return new DbBulkheadAspect(bulkhead);
  }

  /** Aspect that guards annotated methods or types via the configured {@link DbBulkhead}. */
  @Aspect
  @Order(Ordered.HIGHEST_PRECEDENCE + 50)
  public static class DbBulkheadAspect implements AopInfrastructureBean {
    private final DbBulkhead bulkhead;

    /** Creates the aspect bound to the provided {@link DbBulkhead}. */
    public DbBulkheadAspect(DbBulkhead bulkhead) {
      this.bulkhead = Objects.requireNonNull(bulkhead);
    }

    /**
     * Advice that acquires a bulkhead permit around DB-bound work. On rejection, converts to {@link
     * RejectedExecutionException} to align with typical execution semantics.
     */
    @Around(
        "@within(io.veggieshop.platform.starter.data.autoconfig."
            + "DbBulkheadAutoConfiguration.DbLimited) || "
            + "@annotation(io.veggieshop.platform.starter.data.autoconfig."
            + "DbBulkheadAutoConfiguration.DbLimited)")
    public Object limit(ProceedingJoinPoint pjp) throws Throwable {
      DbBulkhead.Guard g = bulkhead.guard();
      try {
        return pjp.proceed();
      } catch (DbConcurrencyLimitExceededException ex) {
        throw new RejectedExecutionException(ex.getMessage(), ex);
      } finally {
        g.close(); // ensure release
      }
    }
  }

  // ------------------------- API: DbBulkhead -------------------------

  /** Thread-safe bulkhead that guards DB-bound sections. */
  public static final class DbBulkhead {
    private final Semaphore semaphore;
    private final int limit;
    private final boolean fair;
    private final Duration acquireTimeout;
    private final Policy policy;

    @Nullable private final MeterRegistry registry;
    @Nullable private final Counter acquired;
    @Nullable private final Counter rejected;
    @Nullable private final Counter timeouts;
    @Nullable private final Timer waitTimer;
    private final AtomicInteger inUse = new AtomicInteger();

    DbBulkhead(
        int limit,
        boolean fair,
        Duration acquireTimeout,
        Policy policy,
        @Nullable MeterRegistry registry) {
      this.limit = limit;
      this.fair = fair;
      this.acquireTimeout = Objects.requireNonNull(acquireTimeout);
      this.policy = Objects.requireNonNull(policy);
      this.semaphore = new Semaphore(limit, fair);
      this.registry = registry;

      if (registry != null) {
        Gauge.builder("db.bulkhead.available", semaphore, Semaphore::availablePermits)
            .description("Available DB bulkhead permits")
            .register(registry);
        Gauge.builder("db.bulkhead.inuse", inUse, AtomicInteger::get)
            .description("In-use DB bulkhead permits")
            .register(registry);
        Gauge.builder("db.bulkhead.limit", () -> this.limit)
            .description("Configured DB bulkhead limit")
            .register(registry);

        this.acquired =
            Counter.builder("db.bulkhead.acquired")
                .tags(Tags.empty())
                .description("Successful bulkhead acquisitions")
                .register(registry);
        this.rejected =
            Counter.builder("db.bulkhead.rejected")
                .tags(Tags.empty())
                .description("Rejected due to bulkhead policy")
                .register(registry);
        this.timeouts =
            Counter.builder("db.bulkhead.timeouts")
                .tags(Tags.empty())
                .description("Timed out waiting for bulkhead")
                .register(registry);
        this.waitTimer =
            Timer.builder("db.bulkhead.wait")
                .description("Time spent waiting for a bulkhead permit")
                .publishPercentileHistogram()
                .register(registry);
      } else {
        this.acquired = null;
        this.rejected = null;
        this.timeouts = null;
        this.waitTimer = null;
      }
    }

    /** Configured concurrency limit. */
    public int limit() {
      return limit;
    }

    /** Currently available permits. */
    public int available() {
      return semaphore.availablePermits();
    }

    /** Acquires a permit and returns a try-with-resources guard. */
    public Guard guard() {
      long start = System.nanoTime();
      boolean ok;
      try {
        ok = semaphore.tryAcquire(acquireTimeout.toNanos(), TimeUnit.NANOSECONDS);
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        ok = false;
      }
      recordWait(start, ok);
      if (!ok) {
        if (policy == Policy.FAIL_FAST || policy == Policy.TIMEOUT_FAIL) {
          if (timeouts != null) {
            timeouts.increment();
          }
          if (rejected != null) {
            rejected.increment();
          }
          throw new DbConcurrencyLimitExceededException(
              "DB bulkhead limit reached (timeout=" + acquireTimeout + ")");
        } else {
          if (rejected != null) {
            rejected.increment();
          }
          throw new DbConcurrencyLimitExceededException("DB bulkhead rejected");
        }
      }
      inUse.incrementAndGet();
      if (acquired != null) {
        acquired.increment();
      }
      return new Guard(this);
    }

    /** Runs a {@link Runnable} within a bulkhead-guarded section. */
    public void run(Runnable task) {
      Guard g = guard();
      try {
        task.run();
      } finally {
        g.close();
      }
    }

    /** Calls a {@link Supplier} within a bulkhead-guarded section and returns its result. */
    public <T> T call(Supplier<T> task) {
      Guard g = guard();
      try {
        return task.get();
      } finally {
        g.close();
      }
    }

    private void releaseInternal() {
      inUse.decrementAndGet();
      semaphore.release();
    }

    private void recordWait(long startNanos, boolean success) {
      if (waitTimer != null) {
        waitTimer.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
      }
      if (!success && timeouts != null) {
        timeouts.increment();
      }
    }

    /** Auto-closeable guard returned by {@link #guard()}. */
    public static final class Guard implements AutoCloseable {
      private final DbBulkhead owner;
      private boolean released;

      Guard(DbBulkhead owner) {
        this.owner = owner;
      }

      @Override
      public void close() {
        if (!released) {
          released = true;
          owner.releaseInternal();
        }
      }
    }
  }

  // ------------------------- Annotation -------------------------

  /**
   * Put on a method/class that executes DB-bound work to be wrapped by the bulkhead automatically.
   */
  @Documented
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD, ElementType.TYPE})
  public @interface DbLimited {}

  // ------------------------- Properties -------------------------

  /**
   * Bulkhead properties.
   *
   * <pre>
   * veggieshop.db.bulkhead.enabled=true
   * veggieshop.db.bulkhead.max-concurrent=0
   * veggieshop.db.bulkhead.headroom-multiplier=1.25
   * veggieshop.db.bulkhead.min-bound=8
   * veggieshop.db.bulkhead.max-bound=128
   * veggieshop.db.bulkhead.fair=true
   * veggieshop.db.bulkhead.acquire-timeout=200ms
   * veggieshop.db.bulkhead.policy=TIMEOUT_FAIL  # WAIT | TIMEOUT_FAIL | FAIL_FAST
   * veggieshop.db.bulkhead.aspect-enabled=true
   * </pre>
   */
  @ConfigurationProperties(prefix = "veggieshop.db.bulkhead")
  public static class DbBulkheadProperties {
    private boolean enabled = true;
    private int maxConcurrent = 0;
    private double headroomMultiplier = 1.25d;
    private int minBound = 8;
    private int maxBound = 128;
    private boolean fair = true;
    private Duration acquireTimeout = Duration.ofMillis(200);
    private Policy policy = Policy.TIMEOUT_FAIL;
    private boolean aspectEnabled = true;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public int getMaxConcurrent() {
      return maxConcurrent;
    }

    public void setMaxConcurrent(int maxConcurrent) {
      this.maxConcurrent = maxConcurrent;
    }

    public double getHeadroomMultiplier() {
      return headroomMultiplier;
    }

    public void setHeadroomMultiplier(double headroomMultiplier) {
      this.headroomMultiplier = headroomMultiplier;
    }

    public int getMinBound() {
      return minBound;
    }

    public void setMinBound(int minBound) {
      this.minBound = minBound;
    }

    public int getMaxBound() {
      return maxBound;
    }

    public void setMaxBound(int maxBound) {
      this.maxBound = maxBound;
    }

    public boolean isFair() {
      return fair;
    }

    public void setFair(boolean fair) {
      this.fair = fair;
    }

    public Duration getAcquireTimeout() {
      return acquireTimeout;
    }

    public void setAcquireTimeout(Duration acquireTimeout) {
      this.acquireTimeout = acquireTimeout;
    }

    public Policy getPolicy() {
      return policy;
    }

    public void setPolicy(Policy policy) {
      this.policy = policy;
    }

    public boolean isAspectEnabled() {
      return aspectEnabled;
    }

    public void setAspectEnabled(boolean aspectEnabled) {
      this.aspectEnabled = aspectEnabled;
    }
  }

  // ------------------------- Policy & Exception -------------------------

  /** Policy for behavior when a permit cannot be acquired. */
  public enum Policy {
    TIMEOUT_FAIL,
    FAIL_FAST,
    WAIT
  }

  /** Exception thrown when the bulkhead limit is exceeded. */
  public static final class DbConcurrencyLimitExceededException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    public DbConcurrencyLimitExceededException(String message) {
      super(message);
    }
  }
}
