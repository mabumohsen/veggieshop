package io.veggieshop.platform.domain.error;

import io.veggieshop.platform.domain.version.EntityVersion;
import io.veggieshop.platform.domain.tenant.TenantId;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.util.*;

/**
 * VeggieException
 *
 * <p>Enterprise-grade, framework-agnostic domain exception aligned with RFC7807 problem details.
 * Designed for use across HTTP and messaging layers while keeping the <em>domain</em> module
 * free of servlet/Spring dependencies.</p>
 *
 * <h2>Key characteristics</h2>
 * <ul>
 *   <li><b>Problem Types:</b> Carries a {@link ProblemTypes.ProblemType} with stable URI, title, and default status.</li>
 *   <li><b>Wire-ready:</b> {@link #toProblemDetails()} exposes a serializable snapshot you can render as
 *       <code>application/problem+json</code> (or log/emit on DLQ).</li>
 *   <li><b>No PII:</b> Extensions are validated (kebab-case keys, JSON-safe values). Do not place PII in detail/extension.</li>
 *   <li><b>Observability:</b> Optional tenant, correlationId, and traceId fields for consistent logs/metrics.</li>
 *   <li><b>Performance:</b> Stack trace capture can be skipped for expected 4xx errors.</li>
 * </ul>
 *
 * <h3>Typical usage</h3>
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

    private final ProblemTypes.ProblemType type;
    private final int status;
    private final String title;
    private final String detail;         // keep non-PII, actionable
    private final String instance;       // absolute/relative URI identifying the occurrence (optional)

    // Observability / multi-tenancy
    private final TenantId tenantId;     // optional; do not rely on this for auth
    private final String correlationId;  // e.g., X-Request-Id
    private final String traceId;        // OTel trace id

    // RFC7807 "extensions" (kebab-case keys; JSON-safe primitive values only)
    private final Map<String, Object> extensions;

    // Performance toggle: avoid stack traces for expected 4xx paths unless explicitly enabled
    private final boolean captureStackTrace;

    private VeggieException(Builder b) {
        super(Objects.requireNonNullElse(b.detail, b.type.title()), b.cause, b.captureStackTrace, b.captureStackTrace);
        this.type = b.type;
        this.status = b.status != null ? b.status : b.type.defaultStatus();
        this.title = Objects.requireNonNullElse(b.title, b.type.title());
        this.detail = b.detail;
        this.instance = b.instance;
        this.tenantId = b.tenantId;
        this.correlationId = b.correlationId;
        this.traceId = b.traceId;
        this.extensions = Collections.unmodifiableMap(new LinkedHashMap<>(b.extensions));
        // if not explicitly specified, default: capture stack for 5xx, skip for 4xx
        this.captureStackTrace = (b.captureStackTrace != null) ? b.captureStackTrace : (this.status >= 500);
    }

    // -------------------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------------------

    public static Builder builder(ProblemTypes.ProblemType type) {
        return new Builder(type);
    }

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

        public Builder status(int status) {
            if (status < 100 || status > 599) {
                throw new IllegalArgumentException("status must be a valid HTTP status code");
            }
            this.status = status;
            return this;
        }

        public Builder title(String title) {
            this.title = requireNonBlank(title, "title");
            return this;
        }

        public Builder detail(String detail) {
            this.detail = requireNonBlank(detail, "detail");
            return this;
        }

        public Builder instance(String instance) {
            if (instance != null && !instance.isBlank()) {
                // Accept absolute or relative; let higher layer constrain if needed
                this.instance = instance.trim();
            }
            return this;
        }

        public Builder tenantId(TenantId tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder correlationId(String correlationId) {
            if (correlationId != null && !correlationId.isBlank()) {
                this.correlationId = safeToken(correlationId, 1, 128);
            }
            return this;
        }

        public Builder traceId(String traceId) {
            if (traceId != null && !traceId.isBlank()) {
                this.traceId = safeToken(traceId, 1, 64);
            }
            return this;
        }

        public Builder extension(String key, Object value) {
            putExtension(this.extensions, key, value);
            return this;
        }

        public Builder extensions(Map<String, ?> map) {
            if (map != null) {
                map.forEach((k, v) -> putExtension(this.extensions, k, v));
            }
            return this;
        }

        /** If true, include stack traces even for 4xx; if false, suppress even for 5xx. */
        public Builder captureStackTrace(boolean captureStackTrace) {
            this.captureStackTrace = captureStackTrace;
            return this;
        }

        public Builder cause(Throwable cause) {
            this.cause = cause;
            return this;
        }

        public VeggieException build() {
            return new VeggieException(this);
        }
    }

    // -------------------------------------------------------------------------------------
    // Factories for common scenarios
    // -------------------------------------------------------------------------------------

    /** 404 resource not found with safe extensions. */
    public static VeggieException notFound(String resourceType, String resourceId, TenantId tenantId) {
        return VeggieException.builder(ProblemTypes.RESOURCE_NOT_FOUND)
                .detail(resourceType + " not found")
                .extension("resource-type", requireCode(resourceType, "resourceType", 1, 80))
                .extension("resource-id", safeToken(resourceId, 1, 120))
                .tenantId(tenantId)
                .captureStackTrace(false)
                .build();
    }

    /** 412 consistency precondition failed (expected vs actual versions). */
    public static VeggieException consistencyFailed(EntityVersion expected, EntityVersion actual,
                                                    String resourceType, String resourceId) {
        return VeggieException.builder(ProblemTypes.CONSISTENCY_PRECONDITION_FAILED)
                .detail("If-Consistent-With does not match current entity version")
                .extension("expected-version", expected != null ? expected.toIfConsistentWith() : "-")
                .extension("current-version", actual != null ? actual.toIfConsistentWith() : "-")
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
     * Snapshot suitable for <code>application/problem+json</code>.
     * Keep values PII-free and JSON-safe. Extensions are returned under the standard "extensions" holder.
     */
    public ProblemDetails toProblemDetails() {
        return new ProblemDetails(
                type.uri(),
                title,
                status,
                detail,
                instance != null ? URI.create(instance) : null,
                tenantId != null ? tenantId.value() : null,
                correlationId,
                traceId,
                extensions
        );
    }

    /** Serializable, framework-neutral structure for RFC7807. */
    public record ProblemDetails(
            URI type,
            String title,
            int status,
            String detail,
            URI instance,
            String tenantId,
            String correlationId,
            String traceId,
            Map<String, Object> extensions
    ) implements Serializable {
        @Serial private static final long serialVersionUID = 1L;
        public ProblemDetails {
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(title, "title");
            if (status < 100 || status > 599) {
                throw new IllegalArgumentException("status must be 100..599");
            }
            extensions = extensions == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(extensions));
        }
    }

    // -------------------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------------------

    @Override
    public ProblemTypes.ProblemType type() { return this.type; }
    public int status() { return this.status; }
    public String title() { return title; }
    public Optional<String> detail() { return Optional.ofNullable(detail); }
    public Optional<String> instance() { return Optional.ofNullable(instance); }
    public Optional<TenantId> tenantId() { return Optional.ofNullable(tenantId); }
    public Optional<String> correlationId() { return Optional.ofNullable(correlationId); }
    public Optional<String> traceId() { return Optional.ofNullable(traceId); }
    public Map<String, Object> extensions() { return extensions; }

    // -------------------------------------------------------------------------------------
    // Object contract (PII-safe)
    // -------------------------------------------------------------------------------------

    @Override
    public String toString() {
        return "VeggieException{" +
                "type=" + type.slug() +
                ", status=" + status +
                ", title='" + title + '\'' +
                ", tenantId=" + (tenantId != null ? tenantId.value() : "-") +
                ", correlationId=" + abbrev(correlationId, 16) +
                ", traceId=" + abbrev(traceId, 16) +
                ", instance=" + abbrev(instance, 32) +
                ", extensions=" + extensions.keySet() +     // keys only (avoid value leakage)
                '}';
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
        if (k.length() > 60) throw new IllegalArgumentException("extension key too long (max 60)");
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
        if (value instanceof Number || value instanceof Boolean) return value;
        throw new IllegalArgumentException("extension value must be a JSON primitive (String/Number/Boolean/null)");
    }

    private static String requireNonBlank(String s, String name) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
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
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
