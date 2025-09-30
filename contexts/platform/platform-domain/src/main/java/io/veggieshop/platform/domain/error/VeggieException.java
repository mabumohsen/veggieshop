package io.veggieshop.platform.domain.error;

import io.veggieshop.platform.domain.tenant.TenantId;
import io.veggieshop.platform.domain.version.EntityVersion;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * VeggieException
 *
 * <p>Enterprise-grade, framework-agnostic domain exception aligned with RFC7807 problem details.
 * Designed for use across HTTP and messaging layers while keeping the <em>domain</em> module free
 * of servlet/Spring dependencies.
 *
 * <h2>Key characteristics</h2>
 *
 * <ul>
 *   <li><b>Problem Types:</b> Carries a {@link ProblemTypes.ProblemType} with stable URI, title,
 *       and default status.
 *   <li><b>Wire-ready:</b> {@link #toProblemDetails()} exposes a serializable snapshot you can
 *       render as <code>application/problem+json</code> (or log/emit on DLQ).
 *   <li><b>No PII:</b> Extensions are validated (kebab-case keys, JSON-safe values). Do not place
 *       PII in detail/extension.
 *   <li><b>Observability:</b> Optional tenant, correlationId, and traceId fields for consistent
 *       logs/metrics.
 *   <li><b>Performance:</b> Stack trace capture can be skipped for expected 4xx errors.
 * </ul>
 *
 * <h3>Typical usage</h3>
 *
 * <pre>{@code
 * // Simple validation failure
 * throw VeggieException.builder(ProblemTypes.VALIDATION_FAILED)
 *     .detail("quantity must be >= 1")
 *     .extension("field", "quantity")
 *     .build();
 *
 * // Resource not found, with safe extensions
 * throw VeggieException.notFound("Order", orderId, tenantId);
 *
 * // Consistency precondition
 * throw VeggieException.consistencyFailed(expectedVersion, currentVersion, "Order", orderId);
 * }</pre>
 */
public final class VeggieException extends RuntimeException implements HasProblemType {

  @Serial private static final long serialVersionUID = 1L;

  // NOTE: class is Serializable via RuntimeException. Mark non-serializable fields as transient.
  private final transient ProblemTypes.ProblemType type;
  private final int status;
  private final String title;
  private final String detail; // keep non-PII, actionable
  private final String instance; // absolute/relative URI identifying the occurrence (optional)

  // Observability / multi-tenancy
  private final transient TenantId tenantId; // optional; domain type likely non-serializable
  private final String correlationId; // e.g., X-Request-Id
  private final String traceId; // OTel trace id

  // RFC7807 "extensions" (kebab-case keys; JSON-safe primitive values only)
  private final transient Map<String, Object> extensions;

  // Performance toggle: avoid stack traces for expected 4xx paths unless explicitly enabled
  private final boolean captureStackTrace;

  private VeggieException(Builder b) {
    // We always keep suppression enabled; 'writable' controls stack-trace capture.
    super(
        Objects.requireNonNullElse(b.detail, b.type.title()),
        b.cause,
        true,
        (b.captureStackTrace != null)
            ? b.captureStackTrace.booleanValue()
            : ((b.status != null ? b.status.intValue() : b.type.defaultStatus()) >= 500));

    this.type = b.type;

    final int resolvedStatus = (b.status != null) ? b.status.intValue() : b.type.defaultStatus();
    this.status = resolvedStatus;

    this.title = Objects.requireNonNullElse(b.title, b.type.title());
    this.detail = b.detail;
    this.instance = b.instance;
    this.tenantId = b.tenantId;
    this.correlationId = b.correlationId;
    this.traceId = b.traceId;
    this.extensions = Collections.unmodifiableMap(new LinkedHashMap<>(b.extensions));
    this.captureStackTrace =
        (b.captureStackTrace != null)
            ? b.captureStackTrace.booleanValue()
            : (resolvedStatus >= 500);
  }

  // -------------------------------------------------------------------------------------
  // Builder
  // -------------------------------------------------------------------------------------

  /**
   * Creates a builder for {@link VeggieException}.
   *
   * @param type the problem type descriptor (must not be null)
   * @return a new {@link Builder}
   */
  public static Builder builder(ProblemTypes.ProblemType type) {
    return new Builder(type);
  }

  /**
   * Fluent builder for {@link VeggieException}.
   *
   * <p>Validates inputs early (ASCII-safe tokens, kebab-case extension keys, JSON-safe values), and
   * allows toggling stack-trace capture.
   */
  public static final class Builder {
    private final ProblemTypes.ProblemType type;

    private Integer status;
    private String title;
    private String detail;
    private String instance;

    private TenantId tenantId;
    private String correlationId;
    private String traceId;

    private final Map<String, Object> extensions = new LinkedHashMap<>();
    private Boolean captureStackTrace;
    private Throwable cause;

    private Builder(ProblemTypes.ProblemType type) {
      this.type = Objects.requireNonNull(type, "type");
    }

    /**
     * Overrides the HTTP status code (100..599).
     *
     * @param status HTTP status
     * @return this builder
     */
    public Builder status(int status) {
      if (status < 100 || status > 599) {
        throw new IllegalArgumentException("status must be a valid HTTP status code");
      }
      this.status = status;
      return this;
    }

    /**
     * Sets a short, human-readable title (non-blank).
     *
     * @param title the title
     * @return this builder
     */
    public Builder title(String title) {
      this.title = requireNonBlank(title, "title");
      return this;
    }

    /**
     * Sets the detail message (non-blank, avoid PII).
     *
     * @param detail detail text
     * @return this builder
     */
    public Builder detail(String detail) {
      this.detail = requireNonBlank(detail, "detail");
      return this;
    }

    /**
     * Sets instance URI string (absolute or relative). Optional.
     *
     * @param instance URI as string
     * @return this builder
     */
    public Builder instance(String instance) {
      if (instance != null && !instance.isBlank()) {
        // Accept absolute or relative; let higher layer constrain if needed
        this.instance = instance.trim();
      }
      return this;
    }

    /**
     * Sets tenant id (optional).
     *
     * @param tenantId tenant id
     * @return this builder
     */
    public Builder tenantId(TenantId tenantId) {
      this.tenantId = tenantId;
      return this;
    }

    /**
     * Sets correlation id (token-safe).
     *
     * @param correlationId correlation id
     * @return this builder
     */
    public Builder correlationId(String correlationId) {
      if (correlationId != null && !correlationId.isBlank()) {
        this.correlationId = safeToken(correlationId, 1, 128);
      }
      return this;
    }

    /**
     * Sets trace id (token-safe).
     *
     * @param traceId trace id
     * @return this builder
     */
    public Builder traceId(String traceId) {
      if (traceId != null && !traceId.isBlank()) {
        this.traceId = safeToken(traceId, 1, 64);
      }
      return this;
    }

    /**
     * Adds one RFC7807 extension entry (kebab-case key, JSON-primitive value).
     *
     * @param key kebab-case key
     * @param value JSON primitive (String/Number/Boolean/null)
     * @return this builder
     */
    public Builder extension(String key, Object value) {
      putExtension(this.extensions, key, value);
      return this;
    }

    /**
     * Adds all RFC7807 extensions from a map (validated).
     *
     * @param map source map (may be null)
     * @return this builder
     */
    public Builder extensions(Map<String, ?> map) {
      if (map != null) {
        map.forEach((k, v) -> putExtension(this.extensions, k, v));
      }
      return this;
    }

    /**
     * Controls stack trace capture. Options:
     *
     * <ul>
     *   <li>true: include stack traces even for 4xx
     *   <li>false: suppress even for 5xx
     *   <li>unset: default (capture for 5xx, skip for 4xx)
     * </ul>
     *
     * @param captureStackTrace flag or null for defaulting
     * @return this builder
     */
    public Builder captureStackTrace(boolean captureStackTrace) {
      this.captureStackTrace = captureStackTrace;
      return this;
    }

    /**
     * Sets the cause to be attached to the exception.
     *
     * <p>We wrap the provided Throwable to avoid storing an externally mutable reference.
     *
     * @param cause original cause (may be null)
     * @return this builder
     */
    public Builder cause(Throwable cause) {
      // Wrap to avoid EI_EXPOSE_REP2; preserves original as suppressed cause of the wrapper.
      if (cause == null) {
        this.cause = null;
      } else {
        RuntimeException wrapper = new RuntimeException(cause.getMessage(), cause);
        this.cause = wrapper;
      }
      return this;
    }

    /** Builds the {@link VeggieException} instance. */
    public VeggieException build() {
      return new VeggieException(this);
    }
  }

  // -------------------------------------------------------------------------------------
  // Factories for common scenarios
  // -------------------------------------------------------------------------------------

  /** 404 resource not found with safe extensions. */
  public static VeggieException notFound(
      String resourceType, String resourceId, TenantId tenantId) {
    return VeggieException.builder(ProblemTypes.RESOURCE_NOT_FOUND)
        .detail(resourceType + " not found")
        .extension("resource-type", requireCode(resourceType, "resourceType", 1, 80))
        .extension("resource-id", safeToken(resourceId, 1, 120))
        .tenantId(tenantId)
        .captureStackTrace(false)
        .build();
  }

  /** 412 consistency precondition failed (expected vs actual versions). */
  public static VeggieException consistencyFailed(
      EntityVersion expected, EntityVersion actual, String resourceType, String resourceId) {
    return VeggieException.builder(ProblemTypes.CONSISTENCY_PRECONDITION_FAILED)
        .detail("If-Consistent-With does not match current entity version")
        .extension("expected-version", (expected != null) ? String.valueOf(expected.value()) : "-")
        .extension("current-version", (actual != null) ? String.valueOf(actual.value()) : "-")
        .extension("resource-type", requireCode(resourceType, "resourceType", 1, 80))
        .extension("resource-id", safeToken(resourceId, 1, 120))
        .captureStackTrace(false)
        .build();
  }

  /** 409 idempotency key conflict. */
  public static VeggieException idempotencyConflict(String idempotencyKey) {
    return VeggieException.builder(ProblemTypes.IDEMPOTENCY_KEY_CONFLICT)
        .detail("Idempotency-Key conflicts with a previous request")
        .extension("idempotency-key", safeToken(idempotencyKey, 1, 100))
        .captureStackTrace(false)
        .build();
  }

  /** 400 validation failure with a field hint. */
  public static VeggieException validation(String message, String field) {
    return VeggieException.builder(ProblemTypes.VALIDATION_FAILED)
        .detail(requireNonBlank(message, "message"))
        .extension("field", requireCode(field, "field", 1, 80))
        .captureStackTrace(false)
        .build();
  }

  // -------------------------------------------------------------------------------------
  // RFC7807 wire representation
  // -------------------------------------------------------------------------------------

  /**
   * Snapshot suitable for <code>application/problem+json</code>. Keep values PII-free and
   * JSON-safe. Extensions are returned under the standard "extensions" holder.
   */
  public ProblemDetails toProblemDetails() {
    return new ProblemDetails(
        type.uri(),
        title,
        status,
        detail,
        (instance != null) ? URI.create(instance) : null,
        (tenantId != null) ? tenantId.value() : null,
        correlationId,
        traceId,
        extensions);
  }

  /**
   * Serializable, framework-neutral structure for RFC7807. Returns defensive copies where
   * applicable.
   */
  public static final class ProblemDetails implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final URI type;
    private final String title;
    private final int status;
    private final String detail;
    private final URI instance;
    private final String tenantId;
    private final String correlationId;
    private final String traceId;
    // Declare as LinkedHashMap (Serializable) to avoid -Werror on non-serializable declared type.
    private final LinkedHashMap<String, Object> extensions;

    /**
     * Constructs a new {@code ProblemDetails}.
     *
     * @param type RFC7807 type URI
     * @param title short, human-readable title
     * @param status HTTP status code (100..599)
     * @param detail detail message (may be null)
     * @param instance instance URI (may be null)
     * @param tenantId tenant identifier (may be null)
     * @param correlationId correlation id (may be null)
     * @param traceId trace id (may be null)
     * @param extensions extensions map; values must be JSON primitives
     */
    public ProblemDetails(
        URI type,
        String title,
        int status,
        String detail,
        URI instance,
        String tenantId,
        String correlationId,
        String traceId,
        Map<String, Object> extensions) {

      this.type = Objects.requireNonNull(type, "type");
      this.title = Objects.requireNonNull(title, "title");
      if (status < 100 || status > 599) {
        throw new IllegalArgumentException("status must be 100..599");
      }
      this.status = status;
      this.detail = detail;
      this.instance = instance;
      this.tenantId = tenantId;
      this.correlationId = correlationId;
      this.traceId = traceId;

      // Store as a concrete, serializable type.
      this.extensions =
          (extensions == null) ? new LinkedHashMap<>() : new LinkedHashMap<>(extensions);
    }

    /** RFC7807 type URI. */
    public URI type() {
      return type;
    }

    /** Short, human-readable title. */
    public String title() {
      return title;
    }

    /** HTTP status code. */
    public int status() {
      return status;
    }

    /** Detail message. */
    public String detail() {
      return detail;
    }

    /** Instance URI (may be null). */
    public URI instance() {
      return instance;
    }

    /** Tenant id (may be null). */
    public String tenantId() {
      return tenantId;
    }

    /** Correlation id (may be null). */
    public String correlationId() {
      return correlationId;
    }

    /** Trace id (may be null). */
    public String traceId() {
      return traceId;
    }

    /**
     * RFC7807 extensions map (defensive copy).
     *
     * @return unmodifiable copy of extensions.
     */
    public Map<String, Object> extensions() {
      return Collections.unmodifiableMap(new LinkedHashMap<>(extensions));
    }
  }

  // -------------------------------------------------------------------------------------
  // Accessors
  // -------------------------------------------------------------------------------------

  @Override
  public ProblemTypes.ProblemType type() {
    return this.type;
  }

  /** Effective HTTP status. */
  public int status() {
    return this.status;
  }

  /** Title (defaults to {@link ProblemTypes.ProblemType#title()}). */
  public String title() {
    return title;
  }

  /** Optional detail text. */
  public Optional<String> detail() {
    return Optional.ofNullable(detail);
  }

  /** Optional instance URI as string. */
  public Optional<String> instance() {
    return Optional.ofNullable(instance);
  }

  /** Optional tenant id. */
  public Optional<TenantId> tenantId() {
    return Optional.ofNullable(tenantId);
  }

  /** Optional correlation id. */
  public Optional<String> correlationId() {
    return Optional.ofNullable(correlationId);
  }

  /** Optional trace id. */
  public Optional<String> traceId() {
    return Optional.ofNullable(traceId);
  }

  /** Unmodifiable view of extensions map. */
  public Map<String, Object> extensions() {
    return extensions;
  }

  // -------------------------------------------------------------------------------------
  // Object contract (PII-safe)
  // -------------------------------------------------------------------------------------

  @Override
  public String toString() {
    return "VeggieException{"
        + "type="
        + ((type != null) ? type.slug() : "-")
        + ", status="
        + status
        + ", title='"
        + title
        + '\''
        + ", tenantId="
        + ((tenantId != null) ? tenantId.value() : "-")
        + ", correlationId="
        + abbrev(correlationId, 16)
        + ", traceId="
        + abbrev(traceId, 16)
        + ", instance="
        + abbrev(instance, 32)
        + ", extensions="
        + extensions.keySet() // keys only (avoid value leakage)
        + '}';
  }

  // -------------------------------------------------------------------------------------
  // Validation helpers (keys/values are ASCII + JSON-safe primitives)
  // -------------------------------------------------------------------------------------

  private static void putExtension(Map<String, Object> target, String key, Object value) {
    String k = requireKebabKey(key);
    Object v = requireJsonPrimitive(value);
    target.put(k, v);
  }

  private static String requireKebabKey(String key) {
    String k = requireNonBlank(key, "extension key").toLowerCase(Locale.ROOT);
    if (k.length() > 60) {
      throw new IllegalArgumentException("extension key too long (max 60)");
    }
    if (!k.matches("[a-z0-9]+(?:-[a-z0-9]+)*")) {
      throw new IllegalArgumentException("extension key must be lower-kebab-case");
    }
    return k;
  }

  private static Object requireJsonPrimitive(Object value) {
    if (value == null) {
      return null; // allow null to express "unknown"
    }
    if (value instanceof String s) {
      if (s.length() > 512) {
        throw new IllegalArgumentException("extension string value too long (max 512)");
      }
      // ASCII preferred; allow UTF-8 if needed by callers—PII still must be avoided by policy
      return s;
    }
    if (value instanceof Number || value instanceof Boolean) {
      return value;
    }
    throw new IllegalArgumentException(
        "extension value must be a JSON primitive (String/Number/Boolean/null)");
  }

  private static String requireNonBlank(String s, String name) {
    if (s == null || s.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return s.trim();
  }

  private static String requireCode(String value, String name, int min, int max) {
    String v = requireNonBlank(value, name);
    if (v.length() < min || v.length() > max) {
      throw new IllegalArgumentException(name + " length must be [" + min + "," + max + "]");
    }
    if (!v.matches("[A-Za-z0-9._:-]+")) {
      throw new IllegalArgumentException(name + " must match [A-Za-z0-9._:-]+");
    }
    return v;
  }

  private static String safeToken(String value, int min, int max) {
    String v = requireNonBlank(value, "token");
    if (v.length() < min || v.length() > max) {
      throw new IllegalArgumentException("token length must be [" + min + "," + max + "]");
    }
    if (!v.matches("[A-Za-z0-9._:@/\\-]+")) {
      throw new IllegalArgumentException("token contains illegal characters");
    }
    return v;
  }

  private static String abbrev(String s, int max) {
    if (s == null) {
      return null;
    }
    return (s.length() <= max) ? s : s.substring(0, max - 1) + "…";
  }
}
