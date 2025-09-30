package io.veggieshop.platform.starter.messaging.autoconfig;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the event de-duplication service. Bound to the prefix {@code
 * veggieshop.dedupe}.
 */
@ConfigurationProperties(prefix = "veggieshop.dedupe")
public class VeggieDedupeProperties {

  // TTL for rows in event_dedupe (minimum in PROD = 7 days).
  private Duration ttl = Duration.ofHours(168); // 7d

  // Minimum accepted version used for idempotency/version checks.
  private long minAcceptedVersion = 0L;

  // Time window within which duplicate/replayed events are rejected.
  private Duration replayWindow = Duration.ofHours(240); // 10d

  // Maximum tolerated future clock skew for event timestamps.
  private Duration maxFutureSkew = Duration.ofMinutes(5);

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
