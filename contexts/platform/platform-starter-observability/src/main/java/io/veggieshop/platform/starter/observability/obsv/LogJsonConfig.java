package io.veggieshop.platform.starter.observability.obsv;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.slf4j.Marker;
import org.slf4j.MDC;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LogJsonConfig
 *
 * Installs JSON logging guards and exposes log sanitation utilities.
 *
 * PRD alignment:
 * - JSON logs with PII guards at runtime (PRD §17)
 * - Works alongside OpenTelemetry tracing (traceId/spanId) and Servlet-only model (PRD §6)
 * - No PII in logs/metrics/traces; deny/allow lists enforced at runtime
 *
 * Behavior:
 * - Registers a Logback TurboFilter (PIIGuardTurboFilter) that scans messages and parameters.
 *   If a blocked pattern is detected (e.g., PAN with Luhn pass, email, CVV), the event is
 *   DENIED (not logged) by default. This fail-closed posture can be relaxed to "mask"
 *   behavior in encoders using the provided LogSanitizer.
 *
 * MDC:
 * - Encourages consistent MDC keys: traceId, spanId, tenantId, requestId.
 *   These keys can be referenced by logback-veggie-default.xml encoders/layouts.
 *
 * Since: 2.0
 */
@AutoConfiguration
@EnableConfigurationProperties(LogJsonProperties.class)
@ConditionalOnClass(LoggerContext.class)
public class LogJsonConfig {

    /**
     * Provide a sanitizer bean to be used by JSON encoders/providers if message masking
     * is desired (e.g., in custom Logstash/Logback providers).
     */
    @Bean
    @ConditionalOnMissingBean
    public LogSanitizer logSanitizer(LogJsonProperties props) {
        return new DefaultLogSanitizer(props);
    }

    /**
     * Lifecycle hook that installs/uninstalls the TurboFilter at runtime.
     * Keeping this as SmartLifecycle ensures proper start/stop ordering.
     */
    @Bean
    public SmartLifecycle piiGuardLifecycle(LoggerContext loggerContext, LogJsonProperties props) {
        return new SmartLifecycle() {
            private volatile boolean running = false;
            private PIIGuardTurboFilter filter;

            @Override public void start() {
                if (running) return;
                // Set useful context properties for logback-veggie-default.xml to reference.
                loggerContext.putProperty("LOG_JSON_ENABLED", "true");
                loggerContext.putProperty("LOG_JSON_CHARSET", StandardCharsets.UTF_8.name());
                loggerContext.putProperty("LOG_JSON_MDC_KEYS", "traceId,spanId,tenantId,requestId");

                if (props.isGuardEnabled()) {
                    filter = new PIIGuardTurboFilter(props);
                    filter.start();
                    loggerContext.addTurboFilter(filter);
                }
                running = true;
            }

            @Override public void stop() {
                if (!running) return;
                if (filter != null) {
                    loggerContext.getTurboFilterList().remove(filter);
                    filter.stop();
                    filter = null;
                }
                running = false;
            }

            @Override public boolean isRunning() {
                return running;
            }

            @Override public int getPhase() {
                // Start after default logging init but early enough to protect early app logs.
                return Integer.MIN_VALUE + 1000;
            }

            @Override public boolean isAutoStartup() {
                return true;
            }

            @Override public void stop(Runnable callback) {
                stop();
                callback.run();
            }
        };
    }

    // ------------------------------------------------------------------------------------------------
    // TurboFilter implementation: deny-on-detection guard for sensitive patterns
    // ------------------------------------------------------------------------------------------------

    /**
     * A Logback TurboFilter that denies logging when a sensitive pattern is detected.
     * Note: TurboFilter cannot alter the message. For masking needs, use LogSanitizer
     * inside the JSON encoder/provider. This filter is intentionally fail-closed by default.
     */
    static final class PIIGuardTurboFilter extends TurboFilter {
        private final LogJsonProperties props;
        private final List<Pattern> blockedPatterns;

        PIIGuardTurboFilter(LogJsonProperties props) {
            this.props = Objects.requireNonNull(props, "props");
            this.blockedPatterns = compilePatterns(props);
        }

        @Override
        public FilterReply decide(Marker marker, Logger logger, Level level, String format,
                                  Object[] params, Throwable t) {
            if (!props.isGuardEnabled()) return FilterReply.NEUTRAL;
            // Skip DEBUG/TRACE if configured to reduce CPU (optional future flag).
            StringBuilder sb = new StringBuilder(256);
            if (format != null) sb.append(format);
            if (params != null && params.length > 0) {
                sb.append(' ');
                for (Object p : params) {
                    if (p != null) sb.append(safeToString(p)).append(' ');
                }
            }
            if (t != null && t.getMessage() != null) {
                sb.append(' ').append(t.getMessage());
            }
            final String candidate = sb.toString();

            // 1) Fast PAN (card) detection with Luhn validation to mitigate false positives.
            if (detectPan(candidate)) {
                // Attach a diagnostic MDC hint for downstream sinks (even if we deny).
                MDC.put("piiFlag", "pan");
                return props.isDenyOnMatch() ? FilterReply.DENY : FilterReply.NEUTRAL;
            }

            // 2) Regex-based detection for emails, CVV/CVC, SSN-like, etc.
            for (Pattern p : blockedPatterns) {
                Matcher m = p.matcher(candidate);
                if (m.find()) {
                    String tag = tagFor(p, m);
                    MDC.put("piiFlag", tag);
                    return props.isDenyOnMatch() ? FilterReply.DENY : FilterReply.NEUTRAL;
                }
            }
            return FilterReply.NEUTRAL;
        }

        private static String safeToString(Object o) {
            try {
                return String.valueOf(o);
            } catch (Throwable ex) {
                return "<unprintable>";
            }
        }

        private static List<Pattern> compilePatterns(LogJsonProperties props) {
            List<Pattern> list = new ArrayList<>();
            // Email
            list.add(Pattern.compile("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"));
            // CVV/CVC (3-4 digits) when preceded by cvv/cvc label
            list.add(Pattern.compile("(?i)\\b(?:cvv|cvc)\\s*[:=]?\\s*([0-9]{3,4})\\b"));
            // SSN-like (US-style) - conservative to avoid noise
            list.add(Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));
            // Generic secret/token keys indicators
            list.add(Pattern.compile("(?i)\\b(api[_-]?key|secret|password|pwd|token)\\s*[:=]\\s*[^\\s\"']+"));
            // Extra custom patterns from properties
            for (String r : props.getExtraBlockedPatterns()) {
                try {
                    list.add(Pattern.compile(r));
                } catch (Exception ignore) {
                    // Ignore invalid patterns to avoid startup failure; can be validated in CI.
                }
            }
            return Collections.unmodifiableList(list);
        }

        private static String tagFor(Pattern p, MatchResult m) {
            String pattern = p.pattern().toLowerCase();
            if (pattern.contains("cvv") || pattern.contains("cvc")) return "cvv";
            if (pattern.contains("api") && pattern.contains("key")) return "api-key";
            if (pattern.contains("secret")) return "secret";
            if (pattern.contains("password") || pattern.contains("pwd")) return "password";
            if (pattern.contains("token")) return "token";
            if (pattern.contains("ssn")) return "ssn";
            if (pattern.contains("@")) return "email";
            return "pii";
        }

        /**
         * Detect potential primary account number (PAN) with Luhn checksum validation.
         * Strips non-digits, searches for digit runs of length 14..19 and validates Luhn.
         */
        private static boolean detectPan(String s) {
            if (s == null || s.isEmpty()) return false;
            int runLen = 0;
            int start = -1;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') {
                    if (runLen == 0) start = i;
                    runLen++;
                    if (runLen >= 14 && runLen <= 19) {
                        if (luhnValidDigits(s.substring(start, i + 1))) return true;
                    } else if (runLen > 19) {
                        // Shift window forward
                        for (int k = start + 1; k <= i - 13; k++) {
                            String sub = digitsOnly(s, k, Math.min(i + 1, k + 19));
                            if (sub.length() >= 14 && sub.length() <= 19 && luhnValidDigits(sub)) return true;
                        }
                    }
                } else {
                    runLen = 0;
                    start = -1;
                }
            }
            return false;
        }

        private static String digitsOnly(String s, int from, int to) {
            StringBuilder b = new StringBuilder(to - from);
            for (int i = from; i < to; i++) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') b.append(c);
            }
            return b.toString();
        }

        /** Luhn checksum validation over a pure-digit string. */
        private static boolean luhnValidDigits(String digits) {
            // Strip any non-digits defensively
            String d = digits.replaceAll("\\D", "");
            int len = d.length();
            if (len < 14 || len > 19) return false;
            int sum = 0;
            boolean dbl = false;
            for (int i = len - 1; i >= 0; i--) {
                int n = d.charAt(i) - '0';
                if (dbl) {
                    n = n * 2;
                    if (n > 9) n -= 9;
                }
                sum += n;
                dbl = !dbl;
            }
            return (sum % 10) == 0;
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Sanitizer (for encoders/providers that prefer masking over denying)
    // ------------------------------------------------------------------------------------------------

    /** Strategy interface for log message sanitation. */
    public interface LogSanitizer {
        /** Returns a sanitized version of the input (never null). */
        String sanitize(String input);
    }

    /** Default sanitizer that masks matched patterns with a replacement token. */
    static final class DefaultLogSanitizer implements LogSanitizer {
        private final LogJsonProperties props;
        private final List<Pattern> patterns;

        DefaultLogSanitizer(LogJsonProperties props) {
            this.props = Objects.requireNonNull(props, "props");
            this.patterns = buildMaskPatterns(props);
        }

        @Override
        public String sanitize(String input) {
            if (input == null || input.isEmpty()) return "";
            String out = input;
            // Mask PAN runs conservatively (even without Luhn here to keep it simple in masking path)
            out = out.replaceAll("(?<!\\d)(?:\\d[ -]?){14,19}(?!\\d)", props.getMaskReplacement());
            for (Pattern p : patterns) {
                out = p.matcher(out).replaceAll(props.getMaskReplacement());
            }
            return out;
        }

        private static List<Pattern> buildMaskPatterns(LogJsonProperties props) {
            List<Pattern> list = new ArrayList<>();
            list.add(Pattern.compile("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"));
            list.add(Pattern.compile("(?i)\\b(?:cvv|cvc)\\s*[:=]?\\s*([0-9]{3,4})\\b"));
            list.add(Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));
            list.add(Pattern.compile("(?i)\\b(api[_-]?key|secret|password|pwd|token)\\s*[:=]\\s*[^\\s\"']+"));
            for (String r : props.getExtraBlockedPatterns()) {
                try { list.add(Pattern.compile(r)); } catch (Exception ignore) { }
            }
            return Collections.unmodifiableList(list);
        }
    }
}
