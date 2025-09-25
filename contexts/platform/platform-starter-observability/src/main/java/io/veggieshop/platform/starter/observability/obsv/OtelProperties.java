package io.veggieshop.platform.starter.observability.obsv;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Enterprise-grade configuration properties for OpenTelemetry across the platform.
 *
 * <p>Prefix: {@code veggieshop.otel}</p>
 *
 * <h3>Design notes</h3>
 * <ul>
 *   <li>Supports both OTLP gRPC and HTTP/Protobuf with sensible defaults.</li>
 *   <li>Signal-specific endpoints (traces/metrics/logs) may be overridden individually.
 *       If not set, they are derived from {@link #endpoint} + protocol.</li>
 *   <li>Batching and timeouts expose OTel SDK defaults with safe enterprise tweaks.</li>
 *   <li>Sampler ratio is ParentBased(traceIdRatioBased) in {@link OtelAutoConfig}.</li>
 *   <li>Baggage allow-list prevents propagating PII by default.</li>
 * </ul>
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.otel")
public class OtelProperties {

    /**
     * Transport protocol for OTLP.
     * <ul>
     *   <li>{@code GRPC}: default port 4317, endpoint is host:port without path.</li>
     *   <li>{@code HTTP}: default port 4318, endpoints include {@code /v1/{signal}} paths.</li>
     * </ul>
     */
    @NotNull
    private Protocol protocol = Protocol.GRPC;

    /**
     * Base endpoint applied to all signals when a per-signal endpoint is not provided.
     * <p>
     * For GRPC, example: {@code http://localhost:4317}.<br/>
     * For HTTP, example: {@code http://localhost:4318} (paths are appended automatically).
     * </p>
     */
    private String endpoint;

    /** Traces exporter endpoint. If unset, derived from {@link #endpoint} + {@link #protocol}. */
    private String tracesEndpoint;

    /** Metrics exporter endpoint. If unset, derived from {@link #endpoint} + {@link #protocol}. */
    private String metricsEndpoint;

    /** Logs exporter endpoint. If unset, derived from {@link #endpoint} + {@link #protocol}. */
    private String logsEndpoint;

    /**
     * Exporter timeout (applies to traces/metrics/logs exporters).
     * Default: 10s (OTel defaults are typically 10s).
     */
    @NotNull
    private Duration exporterTimeout = Duration.ofSeconds(10);

    /**
     * Batch schedule delay for spans/logs processing.
     * Default: 5s (OTel default).
     */
    @NotNull
    private Duration batchScheduleDelay = Duration.ofSeconds(5);

    /**
     * Max queue size for batch processors.
     * Default: 2048 (OTel default).
     */
    @Min(1)
    private int batchMaxQueue = 2048;

    /**
     * Max export batch size for batch processors.
     * Default: 512 (OTel default).
     */
    @Min(1)
    private int batchMaxExportBatchSize = 512;

    /**
     * Periodic metric reader export interval.
     * Default: 60s (balanced overhead vs. freshness).
     */
    @NotNull
    private Duration metricReaderInterval = Duration.ofSeconds(60);

    /**
     * ParentBased + ratio sampler ratio (0.0..1.0).
     * Default: 0.05 (5%) — conservative head sampling; adjust in production as needed.
     */
    @DecimalMin("0.0")
    @DecimalMax("1.0")
    private double traceSampleRatio = 0.05;

    /**
     * Allowed baggage keys to propagate (case-insensitive).
     * Defaults align with PRD: no PII propagation.
     */
    @NotNull
    private List<String> baggageAllowedKeys = new ArrayList<>(List.of("cartId", "orderId", "tenantId"));

    // ======== Derived endpoint logic ========

    private static final String DEFAULT_GRPC_BASE   = "http://localhost:4317";
    private static final String DEFAULT_HTTP_BASE   = "http://localhost:4318";
    private static final String HTTP_TRACES_PATH    = "/v1/traces";
    private static final String HTTP_METRICS_PATH   = "/v1/metrics";
    private static final String HTTP_LOGS_PATH      = "/v1/logs";

    /**
     * Returns the effective traces endpoint based on precedence:
     * <pre>
     * tracesEndpoint (if set)
     * else endpoint + protocol defaults
     * else protocol default (localhost)
     * </pre>
     */
    public String getTracesEndpoint() {
        if (isNonEmpty(tracesEndpoint)) {
            return tracesEndpoint;
        }
        return switch (protocol) {
            case GRPC -> nonEmptyOrDefault(endpoint, DEFAULT_GRPC_BASE);
            case HTTP -> ensureHttpPath(nonEmptyOrDefault(endpoint, DEFAULT_HTTP_BASE), HTTP_TRACES_PATH);
        };
    }

    /** Returns the effective metrics endpoint using the same precedence as {@link #getTracesEndpoint()}. */
    public String getMetricsEndpoint() {
        if (isNonEmpty(metricsEndpoint)) {
            return metricsEndpoint;
        }
        return switch (protocol) {
            case GRPC -> nonEmptyOrDefault(endpoint, DEFAULT_GRPC_BASE);
            case HTTP -> ensureHttpPath(nonEmptyOrDefault(endpoint, DEFAULT_HTTP_BASE), HTTP_METRICS_PATH);
        };
    }

    /** Returns the effective logs endpoint using the same precedence as {@link #getTracesEndpoint()}. */
    public String getLogsEndpoint() {
        if (isNonEmpty(logsEndpoint)) {
            return logsEndpoint;
        }
        return switch (protocol) {
            case GRPC -> nonEmptyOrDefault(endpoint, DEFAULT_GRPC_BASE);
            case HTTP -> ensureHttpPath(nonEmptyOrDefault(endpoint, DEFAULT_HTTP_BASE), HTTP_LOGS_PATH);
        };
    }

    private static String ensureHttpPath(String base, String requiredPath) {
        if (base == null || base.isBlank()) {
            return DEFAULT_HTTP_BASE + requiredPath;
        }
        // Normalize slashes to avoid double slashes when concatenating.
        String normalized = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return normalized.endsWith(requiredPath) ? normalized : normalized + requiredPath;
    }

    private static boolean isNonEmpty(String s) {
        return s != null && !s.isBlank();
    }

    private static String nonEmptyOrDefault(String value, String def) {
        return isNonEmpty(value) ? value : def;
    }

    // ======== Getters / Setters ========

    public Protocol getProtocol() {
        return protocol;
    }

    public void setProtocol(Protocol protocol) {
        this.protocol = protocol == null ? Protocol.GRPC : protocol;
    }

    public String getEndpoint() {
        return endpoint;
    }

    /**
     * Base endpoint for all signals (overridden by per-signal values if provided).
     * For HTTP, do NOT include {@code /v1/traces|metrics|logs}; we will append automatically.
     */
    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getRawTracesEndpoint() {
        return tracesEndpoint;
    }

    public void setTracesEndpoint(String tracesEndpoint) {
        this.tracesEndpoint = tracesEndpoint;
    }

    public String getRawMetricsEndpoint() {
        return metricsEndpoint;
    }

    public void setMetricsEndpoint(String metricsEndpoint) {
        this.metricsEndpoint = metricsEndpoint;
    }

    public String getRawLogsEndpoint() {
        return logsEndpoint;
    }

    public void setLogsEndpoint(String logsEndpoint) {
        this.logsEndpoint = logsEndpoint;
    }

    public Duration getExporterTimeout() {
        return exporterTimeout;
    }

    public void setExporterTimeout(Duration exporterTimeout) {
        this.exporterTimeout = exporterTimeout == null ? Duration.ofSeconds(10) : exporterTimeout;
    }

    public Duration getBatchScheduleDelay() {
        return batchScheduleDelay;
    }

    public void setBatchScheduleDelay(Duration batchScheduleDelay) {
        this.batchScheduleDelay = batchScheduleDelay == null ? Duration.ofSeconds(5) : batchScheduleDelay;
    }

    public int getBatchMaxQueue() {
        return batchMaxQueue;
    }

    public void setBatchMaxQueue(int batchMaxQueue) {
        this.batchMaxQueue = Math.max(1, batchMaxQueue);
    }

    public int getBatchMaxExportBatchSize() {
        return batchMaxExportBatchSize;
    }

    public void setBatchMaxExportBatchSize(int batchMaxExportBatchSize) {
        this.batchMaxExportBatchSize = Math.max(1, batchMaxExportBatchSize);
    }

    public Duration getMetricReaderInterval() {
        return metricReaderInterval;
    }

    public void setMetricReaderInterval(Duration metricReaderInterval) {
        this.metricReaderInterval = metricReaderInterval == null ? Duration.ofSeconds(60) : metricReaderInterval;
    }

    public double getTraceSampleRatio() {
        return traceSampleRatio;
    }

    public void setTraceSampleRatio(double traceSampleRatio) {
        // Keep value in [0,1]; validation also enforces this.
        if (traceSampleRatio < 0.0) traceSampleRatio = 0.0;
        if (traceSampleRatio > 1.0) traceSampleRatio = 1.0;
        this.traceSampleRatio = traceSampleRatio;
    }

    public List<String> getBaggageAllowedKeys() {
        // keep it safe against accidental external mutation
        return Collections.unmodifiableList(baggageAllowedKeys);
    }

    public void setBaggageAllowedKeys(List<String> baggageAllowedKeys) {
        this.baggageAllowedKeys = baggageAllowedKeys == null ? new ArrayList<>() : new ArrayList<>(baggageAllowedKeys);
    }

    // ======== Types ========

    public enum Protocol {
        GRPC, HTTP;
        public boolean isGrpc() { return this == GRPC; }
        public boolean isHttp() { return this == HTTP; }
    }
}
