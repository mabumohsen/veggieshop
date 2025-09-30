package io.veggieshop.platform.starter.observability.obsv;

import static io.opentelemetry.semconv.ServiceAttributes.SERVICE_NAME;
import static io.opentelemetry.semconv.ServiceAttributes.SERVICE_VERSION;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.baggage.BaggageBuilder;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter;
import io.opentelemetry.exporter.otlp.metrics.OtlpGrpcMetricExporter;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.export.PeriodicMetricReader;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Auto-configuration for OpenTelemetry SDK (traces/metrics/logs, propagators, sampler, exporters).
 *
 * <p>Beans provided: {@code Resource}, {@code ContextPropagators}, {@code Sampler}, {@code
 * OpenTelemetry}, {@code Tracer}, plus a shutdown hook to close providers.
 */
@AutoConfiguration
@EnableConfigurationProperties(OtelProperties.class)
@ConditionalOnProperty(
    prefix = "veggieshop.otel",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class OtelAutoConfig {

  private static final AttributeKey<String> SERVICE_NAMESPACE_KEY =
      AttributeKey.stringKey("service.namespace");
  private static final AttributeKey<String> DEPLOYMENT_ENVIRONMENT_KEY =
      AttributeKey.stringKey("deployment.environment");

  // ------------------------------------------------------------------------------------
  // Resource
  // ------------------------------------------------------------------------------------

  /** Builds platform {@link Resource} with service.name/version and deployment.environment. */
  @Bean
  @ConditionalOnMissingBean
  public Resource otelResource(Environment env, Optional<BuildProperties> build) {
    String serviceName = env.getProperty("spring.application.name", "veggieshop");
    String environment =
        env.getProperty(
            "SPRING_PROFILES_ACTIVE", env.getProperty("spring.profiles.active", "default"));
    String version = build.map(BuildProperties::getVersion).orElse("0.0.0");

    Attributes attrs =
        Attributes.builder()
            .put(SERVICE_NAME, serviceName)
            .put(SERVICE_NAMESPACE_KEY, "veggieshop")
            .put(SERVICE_VERSION, version)
            .put(DEPLOYMENT_ENVIRONMENT_KEY, environment)
            .build();

    return Resource.getDefault().merge(Resource.create(attrs));
  }

  // ------------------------------------------------------------------------------------
  // Propagators (TraceContext + Filtered Baggage)
  // ------------------------------------------------------------------------------------

  /** Registers W3C TraceContext + baggage propagators (allow-list for baggage keys). */
  @Bean
  @ConditionalOnMissingBean
  public ContextPropagators otelPropagators(OtelProperties props) {
    TextMapPropagator trace = W3CTraceContextPropagator.getInstance();
    TextMapPropagator baggage =
        new FilteredBaggagePropagator(
            W3CBaggagePropagator.getInstance(), props.getBaggageAllowedKeys());
    return ContextPropagators.create(TextMapPropagator.composite(trace, baggage));
  }

  // ------------------------------------------------------------------------------------
  // Sampler
  // ------------------------------------------------------------------------------------

  /** ParentBased(traceIdRatioBased) sampler using configured ratio. */
  @Bean
  @ConditionalOnMissingBean
  public Sampler otelSampler(OtelProperties props) {
    return Sampler.parentBased(Sampler.traceIdRatioBased(props.getTraceSampleRatio()));
  }

  // ------------------------------------------------------------------------------------
  // Tracer/Meter/Logger Providers + OTLP exporters
  // ------------------------------------------------------------------------------------

  /**
   * Wires SDK providers + OTLP exporters (gRPC/HTTP) per properties and returns {@link
   * OpenTelemetry}.
   */
  @Bean
  @ConditionalOnMissingBean
  public OpenTelemetry openTelemetry(
      Resource resource, ContextPropagators propagators, Sampler sampler, OtelProperties props) {
    // ---- Traces ----
    BatchSpanProcessor spanProcessor =
        BatchSpanProcessor.builder(
                props.getProtocol().isGrpc()
                    ? OtlpGrpcSpanExporter.builder()
                        .setEndpoint(props.getTracesEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build()
                    : OtlpHttpSpanExporter.builder()
                        .setEndpoint(props.getTracesEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build())
            .setScheduleDelay(props.getBatchScheduleDelay())
            .setExporterTimeout(props.getExporterTimeout())
            .setMaxQueueSize(props.getBatchMaxQueue())
            .setMaxExportBatchSize(props.getBatchMaxExportBatchSize())
            .build();

    SdkTracerProvider tracerProvider =
        SdkTracerProvider.builder()
            .setResource(resource)
            .addSpanProcessor(spanProcessor)
            .setSampler(sampler)
            .build();

    // ---- Metrics ----
    PeriodicMetricReader metricReader =
        PeriodicMetricReader.builder(
                props.getProtocol().isGrpc()
                    ? OtlpGrpcMetricExporter.builder()
                        .setEndpoint(props.getMetricsEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build()
                    : OtlpHttpMetricExporter.builder()
                        .setEndpoint(props.getMetricsEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build())
            .setInterval(props.getMetricReaderInterval())
            .build();

    SdkMeterProvider meterProvider =
        SdkMeterProvider.builder().setResource(resource).registerMetricReader(metricReader).build();

    // ---- Logs ----
    BatchLogRecordProcessor logProcessor =
        BatchLogRecordProcessor.builder(
                props.getProtocol().isGrpc()
                    ? OtlpGrpcLogRecordExporter.builder()
                        .setEndpoint(props.getLogsEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build()
                    : OtlpHttpLogRecordExporter.builder()
                        .setEndpoint(props.getLogsEndpoint())
                        .setTimeout(props.getExporterTimeout())
                        .build())
            .setScheduleDelay(props.getBatchScheduleDelay())
            .setExporterTimeout(props.getExporterTimeout())
            .setMaxQueueSize(props.getBatchMaxQueue())
            .setMaxExportBatchSize(props.getBatchMaxExportBatchSize())
            .build();

    SdkLoggerProvider loggerProvider =
        SdkLoggerProvider.builder()
            .setResource(resource)
            .addLogRecordProcessor(logProcessor)
            .build();

    // ---- OpenTelemetry SDK ----
    OpenTelemetrySdk sdk =
        OpenTelemetrySdk.builder()
            .setTracerProvider(tracerProvider)
            .setMeterProvider(meterProvider)
            .setLoggerProvider(loggerProvider)
            .setPropagators(propagators)
            .build();

    GlobalOpenTelemetry.set(sdk);
    return sdk;
  }

  /** Platform {@link Tracer} namespace. */
  @Bean
  @ConditionalOnMissingBean
  public Tracer platformTracer(OpenTelemetry otel) {
    return otel.getTracer("io.veggieshop.platform");
  }

  /** Graceful shutdown for SDK providers. */
  @Bean
  public DisposableBean otelShutdownHook(OpenTelemetry otel) {
    return () -> {
      if (otel instanceof OpenTelemetrySdk sdk) {
        Optional.ofNullable(sdk.getSdkTracerProvider()).ifPresent(SdkTracerProvider::shutdown);
        Optional.ofNullable(sdk.getSdkMeterProvider()).ifPresent(SdkMeterProvider::close);
        Optional.ofNullable(sdk.getSdkLoggerProvider()).ifPresent(SdkLoggerProvider::shutdown);
      }
    };
  }

  // ====================================================================================
  // Helper types
  // ====================================================================================

  /** Baggage propagator with allow-list only (case-insensitive). */
  static final class FilteredBaggagePropagator implements TextMapPropagator {
    private final TextMapPropagator delegate;
    private final Set<String> allowedKeysLower;

    FilteredBaggagePropagator(TextMapPropagator delegate, List<String> allowedKeys) {
      this(delegate, (Collection<String>) allowedKeys);
    }

    FilteredBaggagePropagator(TextMapPropagator delegate, Collection<String> allowedKeys) {
      this.delegate = Objects.requireNonNull(delegate, "delegate");
      this.allowedKeysLower =
          allowedKeys == null
              ? Set.of()
              : allowedKeys.stream()
                  .filter(Objects::nonNull)
                  .map(s -> s.toLowerCase(Locale.ROOT))
                  .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public <C> void inject(Context context, C carrier, TextMapSetter<C> setter) {
      Baggage current = Baggage.fromContext(context);
      BaggageBuilder filtered = Baggage.builder();
      current.forEach(
          (key, entry) -> {
            if (allowedKeysLower.contains(key.toLowerCase(Locale.ROOT))) {
              filtered.put(key, entry.getValue(), entry.getMetadata());
            }
          });
      Context filteredCtx = filtered.build().storeInContext(context);
      delegate.inject(filteredCtx, carrier, setter);
    }

    @Override
    public <C> Context extract(Context context, C carrier, TextMapGetter<C> getter) {
      Context extracted = delegate.extract(context, carrier, getter);
      Baggage all = Baggage.fromContext(extracted);
      BaggageBuilder filtered = Baggage.builder();
      all.forEach(
          (key, entry) -> {
            if (allowedKeysLower.contains(key.toLowerCase(Locale.ROOT))) {
              filtered.put(key, entry.getValue(), entry.getMetadata());
            }
          });
      return filtered.build().storeInContext(context);
    }

    @Override
    public Collection<String> fields() {
      return delegate.fields();
    }
  }
}
