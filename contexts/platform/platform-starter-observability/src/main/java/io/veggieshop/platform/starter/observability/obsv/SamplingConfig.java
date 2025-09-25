package io.veggieshop.platform.starter.observability.obsv;

import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.trace.data.LinkData;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import io.opentelemetry.sdk.trace.samplers.SamplingResult;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * SamplingConfig
 *
 * Optional rule-based head sampler for VeggieShop services.
 * This complements tail-based sampling at the collector by providing targeted
 * head sampling during incidents or for critical paths, while respecting parent
 * sampling decisions.
 *
 * PRD alignment:
 * - Tail-based sampling at collector; dynamic head sampling (incident=100%, targeted paths) (PRD §17)
 * - No PII propagation; force-sample via explicit baggage allow-list only
 * - Servlet + Virtual Threads friendly (PRD §6)
 *
 * Activation:
 * - Enabled only if `veggieshop.obsv.sampling.rules-enabled=true`.
 * - Otherwise, the default sampler from OtelAutoConfig (ParentBased + Ratio) remains in effect.
 *
 * Since: 2.0
 */
@AutoConfiguration
@EnableConfigurationProperties(SamplingConfig.SamplingProperties.class)
public class SamplingConfig {

    /**
     * Rule-based Sampler bean. Takes precedence only when rules are enabled.
     */
    @Bean
    @ConditionalOnProperty(prefix = "veggieshop.obsv.sampling", name = "rules-enabled", havingValue = "true")
    @ConditionalOnMissingBean(Sampler.class)
    public Sampler ruleBasedSampler(SamplingProperties props) {
        return new RuleBasedSampler(props);
    }

    // -------------------------------------------------------------------------------------
    // Implementation
    // -------------------------------------------------------------------------------------

    static final class RuleBasedSampler implements Sampler {
        private static final AttributeKey<String> HTTP_ROUTE  = AttributeKey.stringKey("http.route");
        private static final AttributeKey<String> HTTP_TARGET = AttributeKey.stringKey("http.target");
        private static final AttributeKey<String> URL_PATH    = AttributeKey.stringKey("url.path");
        private static final AttributeKey<String> MSG_SYSTEM  = AttributeKey.stringKey("messaging.system");
        private static final AttributeKey<String> MSG_OP      = AttributeKey.stringKey("messaging.operation");

        private final SamplingProperties props;
        private final Sampler parentBasedRatio;
        private final Sampler alwaysOn  = Sampler.alwaysOn();
        private final Sampler alwaysOff = Sampler.alwaysOff();

        private final List<Pattern> dropName;
        private final List<Pattern> priorityRoutes;

        RuleBasedSampler(SamplingProperties props) {
            this.props = Objects.requireNonNull(props, "props");
            this.parentBasedRatio = Sampler.parentBased(Sampler.traceIdRatioBased(props.getHeadSampleRatio()));

            this.dropName = compile(props.getDropSpanNamePatterns());
            this.priorityRoutes = compile(props.getPriorityRoutePatterns());
        }

        @Override
        public SamplingResult shouldSample(
                Context parentContext,
                String traceId,
                String name,
                SpanKind spanKind,
                Attributes attributes,
                List<LinkData> parentLinks) {

            // 1) Incident mode => sample everything (record & sample)
            if (props.isIncidentMode()) {
                return alwaysOn.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
            }

            // 2) Drop obvious noise by span name (e.g., health/metrics)
            if (matchesAny(name, dropName)) {
                return alwaysOff.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
            }

            // 3) Force-sample via baggage (e.g., set by HTTP filter: X-Debug-Sample)
            if (forceSampleFromBaggage(parentContext, props.getForceBaggageKeys())) {
                return alwaysOn.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
            }

            // 4) Priority HTTP routes: checkout/orders/payments => AlwaysOn
            String route = firstNonNull(
                    attributes.get(HTTP_ROUTE),
                    attributes.get(HTTP_TARGET),
                    attributes.get(URL_PATH));
            if (route != null && matchesAny(route, priorityRoutes)) {
                return alwaysOn.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
            }

            // 5) Kafka consumers (optional): force sample to debug processing paths
            if (spanKind == SpanKind.CONSUMER && props.isSampleKafkaConsumers()) {
                String system = attributes.get(MSG_SYSTEM);
                String op     = attributes.get(MSG_OP);
                if ("kafka".equals(system) && (op == null || "process".equals(op) || "receive".equals(op))) {
                    return alwaysOn.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
                }
            }

            // 6) Fallback to ParentBased + Ratio
            return parentBasedRatio.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
        }

        @Override
        public String getDescription() {
            return "VeggieShopRuleBasedSampler(parentBased:" + props.getHeadSampleRatio() + ")";
        }

        // ---- helpers ----

        private static boolean forceSampleFromBaggage(Context ctx, List<String> keys) {
            Baggage bag = Baggage.fromContext(ctx);
            for (String k : keys) {
                String v = bag.getEntryValue(k);
                if (v != null) {
                    String s = v.trim().toLowerCase(Locale.ROOT);
                    if ("1".equals(s) || "true".equals(s) || "yes".equals(s)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private static List<Pattern> compile(List<String> regexes) {
            List<Pattern> out = new ArrayList<>(regexes.size());
            for (String r : regexes) {
                try {
                    out.add(Pattern.compile(r));
                } catch (Exception ignored) {
                    // Avoid startup failure on invalid patterns; validate in CI.
                }
            }
            return out;
        }

        private static boolean matchesAny(String s, List<Pattern> patterns) {
            if (s == null) return false;
            for (Pattern p : patterns) {
                if (p.matcher(s).find()) return true;
            }
            return false;
        }

        @SafeVarargs
        private static <T> T firstNonNull(T... vals) {
            for (T v : vals) if (v != null) return v;
            return null;
        }
    }

    // -------------------------------------------------------------------------------------
    // Properties (inner class to keep this file self-contained)
    // -------------------------------------------------------------------------------------

    /**
     * Configuration for rule-based head sampling.
     */
    @ConfigurationProperties(prefix = "veggieshop.obsv.sampling")
    public static class SamplingProperties {

        /**
         * Enable the rule-based sampler. If false, the default sampler from OtelAutoConfig applies.
         */
        private boolean rulesEnabled = false;

        /**
         * Incident mode: when true, sample 100% to maximize observability during incidents.
         * Prefer enabling this via configuration/feature flag during on-call events.
         */
        private boolean incidentMode = false;

        /**
         * Default head sampling ratio when none of the rules match (0.0..1.0).
         * ParentBased + traceIdRatioBased(headSampleRatio).
         */
        private double headSampleRatio = 0.10d;

        /**
         * Force-sample via baggage keys (case-insensitive values: 1/true/yes).
         * These baggage keys must be allow-listed at propagation level as well.
         */
        private List<String> forceBaggageKeys = List.of("forceSample");

        /**
         * Drop spans whose names match any of these regex patterns (noise).
         */
        private List<String> dropSpanNamePatterns = List.of(
                "^Health",                            // Spring Boot health endpoints
                "Prometheus",                         // Metrics scrape
                "ClientOutOfOrder",                   // Noisy internal spans (example)
                "DispatcherServlet\\#doService"       // Framework plumbing
        );

        /**
         * Priority HTTP routes (regex). Matching requests are always sampled.
         */
        private List<String> priorityRoutePatterns = List.of(
                "^/v1/checkout.*",
                "^/v1/orders.*",
                "^/v1/payments.*"
        );

        /**
         * For Kafka CONSUMER spans, force sampling (useful for debugging processing pipelines).
         */
        private boolean sampleKafkaConsumers = false;

        // ---- getters/setters ----

        public boolean isRulesEnabled() { return rulesEnabled; }
        public void setRulesEnabled(boolean rulesEnabled) { this.rulesEnabled = rulesEnabled; }

        public boolean isIncidentMode() { return incidentMode; }
        public void setIncidentMode(boolean incidentMode) { this.incidentMode = incidentMode; }

        public double getHeadSampleRatio() { return headSampleRatio; }
        public void setHeadSampleRatio(double headSampleRatio) { this.headSampleRatio = headSampleRatio; }

        public List<String> getForceBaggageKeys() { return forceBaggageKeys; }
        public void setForceBaggageKeys(List<String> forceBaggageKeys) { this.forceBaggageKeys = forceBaggageKeys; }

        public List<String> getDropSpanNamePatterns() { return dropSpanNamePatterns; }
        public void setDropSpanNamePatterns(List<String> dropSpanNamePatterns) { this.dropSpanNamePatterns = dropSpanNamePatterns; }

        public List<String> getPriorityRoutePatterns() { return priorityRoutePatterns; }
        public void setPriorityRoutePatterns(List<String> priorityRoutePatterns) { this.priorityRoutePatterns = priorityRoutePatterns; }

        public boolean isSampleKafkaConsumers() { return sampleKafkaConsumers; }
        public void setSampleKafkaConsumers(boolean sampleKafkaConsumers) { this.sampleKafkaConsumers = sampleKafkaConsumers; }
    }
}
