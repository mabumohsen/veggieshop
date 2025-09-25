package io.veggieshop.platform.starter.messaging.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "veggieshop.outbox")
public class VeggieOutboxProperties {

    private String table = "platform_outbox";
    private int batchSize = 200;
    private int parallelism = 8;
    private int maxAttempts = 20;
    private Duration backoffBase = Duration.ofSeconds(1);
    private Duration backoffMax = Duration.ofMinutes(5);

    /**
     * التحكم بالجدولة من الـstarter فقط
     */
    private Scheduler scheduler = new Scheduler();

    public static class Scheduler {
        private boolean enabled = true;
        /**
         * تأخير البداية
         */
        private Duration initialDelay = Duration.ofSeconds(1);
        /**
         * الفاصل بين الدورات (fixedDelay)
         */
        private Duration interval = Duration.ofMillis(250);
        private int burstBatches = 3;
        private Duration maxBurstDuration = Duration.ofSeconds(2);
        private Duration idleSleep = Duration.ofSeconds(1);

        // --- getters/setters ---
        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getInitialDelay() {
            return initialDelay;
        }

        public void setInitialDelay(Duration initialDelay) {
            this.initialDelay = initialDelay;
        }

        public Duration getInterval() {
            return interval;
        }

        public void setInterval(Duration interval) {
            this.interval = interval;
        }

        public int getBurstBatches() {
            return burstBatches;
        }

        public void setBurstBatches(int burstBatches) {
            this.burstBatches = burstBatches;
        }

        public Duration getMaxBurstDuration() {
            return maxBurstDuration;
        }

        public void setMaxBurstDuration(Duration maxBurstDuration) {
            this.maxBurstDuration = maxBurstDuration;
        }

        public Duration getIdleSleep() {
            return idleSleep;
        }

        public void setIdleSleep(Duration idleSleep) {
            this.idleSleep = idleSleep;
        }
    }

    // --- getters/setters ---
    public String getTable() {
        return table;
    }

    public void setTable(String table) {
        this.table = table;
    }

    public int getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    public int getParallelism() {
        return parallelism;
    }

    public void setParallelism(int parallelism) {
        this.parallelism = parallelism;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public Duration getBackoffBase() {
        return backoffBase;
    }

    public void setBackoffBase(Duration backoffBase) {
        this.backoffBase = backoffBase;
    }

    public Duration getBackoffMax() {
        return backoffMax;
    }

    public void setBackoffMax(Duration backoffMax) {
        this.backoffMax = backoffMax;
    }

    public Scheduler getScheduler() {
        return scheduler;
    }

    public void setScheduler(Scheduler scheduler) {
        this.scheduler = scheduler;
    }
}
