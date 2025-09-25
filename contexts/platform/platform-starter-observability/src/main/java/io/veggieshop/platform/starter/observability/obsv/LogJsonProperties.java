package io.veggieshop.platform.starter.observability.obsv;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for JSON logging & PII guards.
 *
 * Since: 2.0
 */
@ConfigurationProperties(prefix = "veggieshop.obsv.logs")
public class LogJsonProperties {

    /** Enable runtime PII guard (TurboFilter). */
    private boolean guardEnabled = true;

    /**
     * Fail-closed posture: deny the logging event when a sensitive pattern is detected.
     * If set to false, the guard will allow the event; masking should then be applied by encoders.
     */
    private boolean denyOnMatch = true;

    /** Replacement token for masking (used by LogSanitizer). */
    private String maskReplacement = "***";

    /** Additional blocked regex patterns (advanced use). */
    private List<String> extraBlockedPatterns = new ArrayList<>();

    public boolean isGuardEnabled() { return guardEnabled; }
    public void setGuardEnabled(boolean guardEnabled) { this.guardEnabled = guardEnabled; }

    public boolean isDenyOnMatch() { return denyOnMatch; }
    public void setDenyOnMatch(boolean denyOnMatch) { this.denyOnMatch = denyOnMatch; }

    public String getMaskReplacement() { return maskReplacement; }
    public void setMaskReplacement(String maskReplacement) { this.maskReplacement = maskReplacement; }

    public List<String> getExtraBlockedPatterns() { return extraBlockedPatterns; }
    public void setExtraBlockedPatterns(List<String> extraBlockedPatterns) { this.extraBlockedPatterns = extraBlockedPatterns; }
}
