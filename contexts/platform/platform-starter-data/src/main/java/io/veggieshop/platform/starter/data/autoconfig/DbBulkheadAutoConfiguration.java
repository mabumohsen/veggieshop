package io.veggieshop.platform.starter.data.autoconfig;

import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.Nullable;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import javax.sql.DataSource;
import java.lang.annotation.*;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

@AutoConfiguration
@AutoConfigureAfter({ DataSourceAutoConfiguration.class })
@EnableConfigurationProperties(DbBulkheadAutoConfiguration.DbBulkheadProperties.class)
@ConditionalOnClass({ DataSource.class })
@ConditionalOnProperty(prefix = "veggieshop.db.bulkhead", name = "enabled", havingValue = "true", matchIfMissing = true)
public class DbBulkheadAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(DbBulkheadAutoConfiguration.class);

    // ------------------------- Bean: DbBulkhead -------------------------

    @Bean
    @ConditionalOnMissingBean
    public DbBulkhead dbBulkhead(DbBulkheadProperties props,
                                 ObjectProvider<DataSource> dataSource,
                                 ObjectProvider<MeterRegistry> registry) {
        int computedLimit = computeLimit(props, dataSource.getIfAvailable());
        DbBulkhead bulkhead = new DbBulkhead(computedLimit, props.isFair(), props.getAcquireTimeout(),
                props.getPolicy(), registry.getIfAvailable());
        log.info("DB Bulkhead initialized: limit={}, fair={}, acquireTimeout={}, policy={}",
                computedLimit, props.isFair(), props.getAcquireTimeout(), props.getPolicy());
        return bulkhead;
    }

    private static int computeLimit(DbBulkheadProperties props, @Nullable DataSource ds) {
        if (!props.isEnabled()) {
            return Integer.MAX_VALUE; // لا حد فعلي
        }
        if (props.getMaxConcurrent() > 0) {
            return props.getMaxConcurrent();
        }
        // اشتقاق من maximumPoolSize في Hikari إن وُجد
        int base = 32; // افتراضي معقول
        if (ds instanceof HikariDataSource hikari) {
            base = Math.max(1, hikari.getMaximumPoolSize());
        }
        double mult = Math.max(1.0, props.getHeadroomMultiplier());
        long candidate = Math.round(Math.floor(base * mult));
        int bounded = (int) Math.max(props.getMinBound(), Math.min(props.getMaxBound(), candidate));
        return Math.max(1, bounded);
    }

    // ------------------------- Aspect (اختياري) -------------------------

    @Bean
    @ConditionalOnClass(name = "org.aspectj.lang.JoinPoint")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "veggieshop.db.bulkhead", name = "aspect-enabled", havingValue = "true", matchIfMissing = true)
    public DbBulkheadAspect dbBulkheadAspect(DbBulkhead bulkhead) {
        return new DbBulkheadAspect(bulkhead);
    }

    @Aspect
    @Order(Ordered.HIGHEST_PRECEDENCE + 50)
    public static class DbBulkheadAspect implements AopInfrastructureBean {
        private final DbBulkhead bulkhead;

        public DbBulkheadAspect(DbBulkhead bulkhead) {
            this.bulkhead = Objects.requireNonNull(bulkhead);
        }

        @Around("@within(io.veggieshop.platform.starter.data.autoconfig.DbBulkheadAutoConfiguration.DbLimited) || " +
                "@annotation(io.veggieshop.platform.starter.data.autoconfig.DbBulkheadAutoConfiguration.DbLimited)")
        public Object limit(ProceedingJoinPoint pjp) throws Throwable {
            try (DbBulkhead.Guard ignored = bulkhead.guard()) {
                return pjp.proceed();
            } catch (DbConcurrencyLimitExceededException ex) {
                throw new RejectedExecutionException(ex.getMessage(), ex);
            }
        }
    }

    // ------------------------- API: DbBulkhead -------------------------

    /** Bulkhead يحرس المقاطع المتجهة للـDB. Thread-safe. */
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

        DbBulkhead(int limit, boolean fair, Duration acquireTimeout, Policy policy, @Nullable MeterRegistry registry) {
            this.limit = limit;
            this.fair = fair;
            this.acquireTimeout = Objects.requireNonNull(acquireTimeout);
            this.policy = Objects.requireNonNull(policy);
            this.semaphore = new Semaphore(limit, fair);
            this.registry = registry;

            if (registry != null) {
                Tags tags = Tags.empty();
                Gauge.builder("db.bulkhead.available", semaphore, Semaphore::availablePermits)
                        .description("Available DB bulkhead permits").register(registry);
                Gauge.builder("db.bulkhead.inuse", inUse, AtomicInteger::get)
                        .description("In-use DB bulkhead permits").register(registry);
                Gauge.builder("db.bulkhead.limit", () -> this.limit)
                        .description("Configured DB bulkhead limit").register(registry);

                this.acquired = Counter.builder("db.bulkhead.acquired").tags(tags)
                        .description("Successful bulkhead acquisitions").register(registry);
                this.rejected = Counter.builder("db.bulkhead.rejected").tags(tags)
                        .description("Rejected due to bulkhead policy").register(registry);
                this.timeouts = Counter.builder("db.bulkhead.timeouts").tags(tags)
                        .description("Timed out waiting for bulkhead").register(registry);
                this.waitTimer = Timer.builder("db.bulkhead.wait")
                        .description("Time spent waiting for a bulkhead permit")
                        .publishPercentileHistogram()
                        .register(registry);
            } else {
                this.acquired = this.rejected = this.timeouts = null;
                this.waitTimer = null;
            }
        }

        public int limit() { return limit; }
        public int available() { return semaphore.availablePermits(); }

        /** try-with-resources guard. */
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
                    if (timeouts != null) timeouts.increment();
                    if (rejected != null) rejected.increment();
                    throw new DbConcurrencyLimitExceededException("DB bulkhead limit reached (timeout=" + acquireTimeout + ")");
                } else {
                    if (rejected != null) rejected.increment();
                    throw new DbConcurrencyLimitExceededException("DB bulkhead rejected");
                }
            }
            inUse.incrementAndGet();
            if (acquired != null) acquired.increment();
            return new Guard(this);
        }

        public void run(Runnable task) { try (Guard ignored = guard()) { task.run(); } }
        public <T> T call(Supplier<T> task) { try (Guard ignored = guard()) { return task.get(); } }

        private void releaseInternal() { inUse.decrementAndGet(); semaphore.release(); }
        private void recordWait(long startNanos, boolean success) {
            if (waitTimer != null) waitTimer.record(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);
            if (!success && timeouts != null) timeouts.increment();
        }

        public static final class Guard implements AutoCloseable {
            private final DbBulkhead owner; private boolean released;
            Guard(DbBulkhead owner) { this.owner = owner; }
            @Override public void close() { if (!released) { released = true; owner.releaseInternal(); } }
        }
    }

    // ------------------------- Annotation -------------------------

    /** ضعها على الميثود/الكلاس الذي ينفذ عملًا DB-bound ليُحاط بالـbulkhead تلقائيًا. */
    @Documented
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD, ElementType.TYPE})
    public @interface DbLimited { }

    // ------------------------- Properties -------------------------

    /**
     * خصائص الـBulkhead:
     * veggieshop.db.bulkhead.enabled=true
     * veggieshop.db.bulkhead.max-concurrent=0
     * veggieshop.db.bulkhead.headroom-multiplier=1.25
     * veggieshop.db.bulkhead.min-bound=8
     * veggieshop.db.bulkhead.max-bound=128
     * veggieshop.db.bulkhead.fair=true
     * veggieshop.db.bulkhead.acquire-timeout=200ms
     * veggieshop.db.bulkhead.policy=TIMEOUT_FAIL   # WAIT | TIMEOUT_FAIL | FAIL_FAST
     * veggieshop.db.bulkhead.aspect-enabled=true
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

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxConcurrent() { return maxConcurrent; }
        public void setMaxConcurrent(int maxConcurrent) { this.maxConcurrent = maxConcurrent; }
        public double getHeadroomMultiplier() { return headroomMultiplier; }
        public void setHeadroomMultiplier(double headroomMultiplier) { this.headroomMultiplier = headroomMultiplier; }
        public int getMinBound() { return minBound; }
        public void setMinBound(int minBound) { this.minBound = minBound; }
        public int getMaxBound() { return maxBound; }
        public void setMaxBound(int maxBound) { this.maxBound = maxBound; }
        public boolean isFair() { return fair; }
        public void setFair(boolean fair) { this.fair = fair; }
        public Duration getAcquireTimeout() { return acquireTimeout; }
        public void setAcquireTimeout(Duration acquireTimeout) { this.acquireTimeout = acquireTimeout; }
        public Policy getPolicy() { return policy; }
        public void setPolicy(Policy policy) { this.policy = policy; }
        public boolean isAspectEnabled() { return aspectEnabled; }
        public void setAspectEnabled(boolean aspectEnabled) { this.aspectEnabled = aspectEnabled; }
    }

    /** سلوك عند العجز عن الحصول على تصریح. */
    public enum Policy { TIMEOUT_FAIL, FAIL_FAST, WAIT }

    /** Exception عند تجاوز الحد. */
    public static final class DbConcurrencyLimitExceededException extends RuntimeException {
        public DbConcurrencyLimitExceededException(String message) { super(message); }
    }
}
