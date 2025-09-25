package io.veggieshop.platform.starter.messaging.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "veggieshop.dedupe")
public class VeggieDedupeProperties {
    /**
     * TTL للأسطر في event_dedupe (الحد الأدنى PRD = 7 أيام)
     */
    private Duration ttl = Duration.ofHours(168); // 7d
    private long minAcceptedVersion = 0L;
    private Duration replayWindow = Duration.ofHours(240); // 10d
    private Duration maxFutureSkew = Duration.ofMinutes(5);

    // getters & setters
    public Duration getTtl() {
        return ttl;
    }

    public void setTtl(Duration ttl) {
        this.ttl = ttl;
    }

    public long getMinAcceptedVersion() {
        return minAcceptedVersion;
    }

    public void setMinAcceptedVersion(long v) {
        this.minAcceptedVersion = v;
    }

    public Duration getReplayWindow() {
        return replayWindow;
    }

    public void setReplayWindow(Duration d) {
        this.replayWindow = d;
    }

    public Duration getMaxFutureSkew() {
        return maxFutureSkew;
    }

    public void setMaxFutureSkew(Duration d) {
        this.maxFutureSkew = d;
    }
}
