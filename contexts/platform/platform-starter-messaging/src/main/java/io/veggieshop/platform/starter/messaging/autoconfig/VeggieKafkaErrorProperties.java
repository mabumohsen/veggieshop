package io.veggieshop.platform.starter.messaging.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Error-handling properties for Kafka consumers: quarantine suffix, backoff (max
 * retries/interval/multiplier/jitter), and whether to commit on recovery.
 */
@ConfigurationProperties(prefix = "veggieshop.kafka.error")
public class VeggieKafkaErrorProperties {
  private String quarantineSuffix = ".quarantine";
  private int maxRetries = 3;
  private long initialIntervalMs = 250;
  private double multiplier = 2.0;
  private long maxIntervalMs = 5_000;
  private double jitterFraction = 0.20;
  private boolean commitRecovered = true;

  public String getQuarantineSuffix() {
    return quarantineSuffix;
  }

  public void setQuarantineSuffix(String quarantineSuffix) {
    this.quarantineSuffix = quarantineSuffix;
  }

  public int getMaxRetries() {
    return maxRetries;
  }

  public void setMaxRetries(int maxRetries) {
    this.maxRetries = maxRetries;
  }

  public long getInitialIntervalMs() {
    return initialIntervalMs;
  }

  public void setInitialIntervalMs(long initialIntervalMs) {
    this.initialIntervalMs = initialIntervalMs;
  }

  public double getMultiplier() {
    return multiplier;
  }

  public void setMultiplier(double multiplier) {
    this.multiplier = multiplier;
  }

  public long getMaxIntervalMs() {
    return maxIntervalMs;
  }

  public void setMaxIntervalMs(long maxIntervalMs) {
    this.maxIntervalMs = maxIntervalMs;
  }

  public double getJitterFraction() {
    return jitterFraction;
  }

  public void setJitterFraction(double jitterFraction) {
    this.jitterFraction = jitterFraction;
  }

  public boolean isCommitRecovered() {
    return commitRecovered;
  }

  public void setCommitRecovered(boolean commitRecovered) {
    this.commitRecovered = commitRecovered;
  }
}
