package io.veggieshop.platform.starter.application.autoconfig;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Step-Up authentication properties. Prefix: {@code veggieshop.stepup}. */
@ConfigurationProperties(prefix = "veggieshop.stepup")
public class VeggieStepUpProperties {

  /** Minimum elevation duration in minutes. */
  private int minElevationMinutes = 15;

  /** Maximum elevation duration in minutes. */
  private int maxElevationMinutes = 60;

  /** MFA challenge time-to-live. */
  private Duration challengeTtl = Duration.ofMinutes(5);

  public int getMinElevationMinutes() {
    return minElevationMinutes;
  }

  public void setMinElevationMinutes(int v) {
    this.minElevationMinutes = v;
  }

  public int getMaxElevationMinutes() {
    return maxElevationMinutes;
  }

  public void setMaxElevationMinutes(int v) {
    this.maxElevationMinutes = v;
  }

  public Duration getChallengeTtl() {
    return challengeTtl;
  }

  public void setChallengeTtl(Duration v) {
    this.challengeTtl = v;
  }
}
