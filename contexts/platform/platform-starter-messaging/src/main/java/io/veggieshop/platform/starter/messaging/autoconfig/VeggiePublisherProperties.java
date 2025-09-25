package io.veggieshop.platform.starter.messaging.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "veggieshop.publisher")
public class VeggiePublisherProperties {
    private int maxAttempts = 3;
    private Duration initialBackoff = Duration.ofMillis(250);
    private double backoffMultiplier = 2.0;
    private Duration maxBackoff = Duration.ofSeconds(5);
    private double jitterRatio = 0.20;
    private Duration sendTimeout = Duration.ofSeconds(10);

    public int getMaxAttempts() { return maxAttempts; }
    public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }

    public Duration getInitialBackoff() { return initialBackoff; }
    public void setInitialBackoff(Duration initialBackoff) { this.initialBackoff = initialBackoff; }

    public double getBackoffMultiplier() { return backoffMultiplier; }
    public void setBackoffMultiplier(double backoffMultiplier) { this.backoffMultiplier = backoffMultiplier; }

    public Duration getMaxBackoff() { return maxBackoff; }
    public void setMaxBackoff(Duration maxBackoff) { this.maxBackoff = maxBackoff; }

    public double getJitterRatio() { return jitterRatio; }
    public void setJitterRatio(double jitterRatio) { this.jitterRatio = jitterRatio; }

    public Duration getSendTimeout() { return sendTimeout; }
    public void setSendTimeout(Duration sendTimeout) { this.sendTimeout = sendTimeout; }
}
