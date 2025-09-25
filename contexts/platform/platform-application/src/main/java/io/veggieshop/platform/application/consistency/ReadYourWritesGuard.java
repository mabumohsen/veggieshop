package io.veggieshop.platform.application.consistency;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * ReadYourWritesGuard
 *
 * Waits (briefly) before a READ to honor an If-Consistent-With token's watermark.
 * This is a cooperative "best effort": it avoids long blocking and returns false on timeout.
 */
public final class ReadYourWritesGuard {

    /** Minimal metrics hook (no-op by default). Adapter to Micrometer can implement this. */
    public interface Metrics {
        void recordWaitNanos(long nanos);
        void recordTimeout();
        void recordImmediateHit();
    }

    private static final Metrics NOOP_METRICS = new Metrics() {
        @Override public void recordWaitNanos(long nanos) { /* no-op */ }
        @Override public void recordTimeout() { /* no-op */ }
        @Override public void recordImmediateHit() { /* no-op */ }
    };

    private final ConsistencyService service;
    private final ConsistencyProperties props;
    private final Clock clock;
    private final Metrics metrics;

    public ReadYourWritesGuard(ConsistencyService service,
                               ConsistencyProperties props,
                               Clock clock,
                               Metrics metrics) {
        this.service = Objects.requireNonNull(service, "service");
        this.props   = Objects.requireNonNull(props, "props");
        this.clock   = Objects.requireNonNull(clock, "clock");
        this.metrics = (metrics == null ? NOOP_METRICS : metrics);
    }

    public ReadYourWritesGuard(ConsistencyService service,
                               ConsistencyProperties props,
                               Clock clock) {
        this(service, props, clock, NOOP_METRICS);
    }

    /**
     * If the current request carries If-Consistent-With, wait until the tenant's watermark
     * reaches the requested value or until the configured timeout expires.
     *
     * @return true if requirement satisfied, false if timed out
     */
    public boolean awaitIfRequested() {
        Optional<ConsistencyService.RequestState> st = service.currentRequest();
        if (st.isEmpty()) return true;

        long requiredWm = st.get().requiredWatermarkOrZero();
        if (requiredWm <= 0L) {
            metrics.recordImmediateHit();
            return true;
        }

        String tenant = st.get().tenant();
        final long deadline = clock.millis() + props.rywMaxWait().toMillis();

        long pollMillis = props.rywInitialPoll().toMillis();
        final long maxPollMillis = props.rywMaxPoll().toMillis();

        long waitedNanos = 0L;

        // Fast-path
        if (service.currentWatermark(tenant) >= requiredWm) {
            metrics.recordImmediateHit();
            return true;
        }

        for (;;) {
            // Sleep a bit; prefer Thread.onSpinWait for very small waits, else sleep
            if (pollMillis <= 1) {
                Thread.onSpinWait();
            } else {
                try {
                    TimeUnit.MILLISECONDS.sleep(pollMillis);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    metrics.recordTimeout();
                    return false;
                }
            }
            waitedNanos += TimeUnit.MILLISECONDS.toNanos(Math.max(1, pollMillis));

            if (service.currentWatermark(tenant) >= requiredWm) {
                metrics.recordWaitNanos(waitedNanos);
                return true;
            }
            if (clock.millis() >= deadline) {
                metrics.recordTimeout();
                return false;
            }
            // Exponential-ish backoff up to max
            pollMillis = Math.min(maxPollMillis, pollMillis * 2);
        }
    }
}
