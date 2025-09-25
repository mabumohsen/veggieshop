package io.veggieshop.platform.starter.application.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "veggieshop.stepup")
public class VeggieStepUpProperties {
    /** أقل مدة Elevation بالدقائق */
    private int minElevationMinutes = 15;
    /** أقصى مدة Elevation بالدقائق */
    private int maxElevationMinutes = 60;
    /** صلاحية تحدي الـMFA */
    private Duration challengeTtl = Duration.ofMinutes(5);

    public int getMinElevationMinutes() { return minElevationMinutes; }
    public void setMinElevationMinutes(int v) { this.minElevationMinutes = v; }

    public int getMaxElevationMinutes() { return maxElevationMinutes; }
    public void setMaxElevationMinutes(int v) { this.maxElevationMinutes = v; }

    public Duration getChallengeTtl() { return challengeTtl; }
    public void setChallengeTtl(Duration v) { this.challengeTtl = v; }
}
