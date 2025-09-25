package io.veggieshop.platform.domain.error;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * ProblemTypes
 *
 * <p>Central registry of RFC7807 <em>problem type</em> URIs for VeggieShop.
 * These types are stable, human-readable identifiers meant to be returned by HTTP and
 * messaging layers to convey machine-friendly error semantics.</p>
 *
 * <h2>Principles</h2>
 * <ul>
 *   <li><b>Stable URIs:</b> {@code https://problems.veggieshop.io/{slug}} with lowercase, kebab-case slugs.</li>
 *   <li><b>PRD alignment:</b> covers multi-tenancy, idempotency, consistency tokens,
 *       concurrency, rate limiting, PCI/SCA, webhooks, schema/contracts, and quotas.</li>
 *   <li><b>Framework-agnostic:</b> pure JDK 21; no Spring or servlet dependencies here.</li>
 *   <li><b>Interoperability:</b> each type carries a sensible <i>default</i> HTTP status and a short title.
 *       Actual status codes are chosen by higher layers but should default to these.</li>
 * </ul>
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * ProblemTypes.ProblemType t = ProblemTypes.IDEMPOTENCY_KEY_CONFLICT;
 * // t.uri() -> https://problems.veggieshop.io/idempotency-key-conflict
 * // t.defaultStatus() -> 409
 * // t.title() -> "Idempotency Key Conflict"
 *
 * // In HTTP layer (@ControllerAdvice):
 * // return application/problem+json with:
 * //   "type": t.uri(), "title": t.title(), "status": t.defaultStatus(), "detail": "...", "instance": "..."
 * }</pre>
 */
public final class ProblemTypes {

    /** Base authority for all problem type URIs. Keep stable across versions. */
    public static final String BASE = "https://problems.veggieshop.io";

    private static final Map<String, ProblemType> REGISTRY;

    // -------------------------------------------------------------------------------------
    // Core, authn/z, multi-tenancy
    // -------------------------------------------------------------------------------------

    /** 400 – Required tenant was not supplied. */
    public static final ProblemType TENANT_REQUIRED =
            def("tenant-required", "Tenant Required", 400);

    /** 404 – Supplied tenant does not exist or is disabled. */
    public static final ProblemType TENANT_UNKNOWN =
            def("tenant-unknown", "Unknown Tenant", 404);

    /** 403 – Token tenant differs from request tenant. */
    public static final ProblemType TENANT_MISMATCH =
            def("tenant-mismatch", "Tenant Mismatch", 403);

    /** 401 – Invalid/missing/expired credentials. */
    public static final ProblemType AUTHENTICATION_FAILED =
            def("authentication-failed", "Authentication Failed", 401);

    /** 403 – Caller is authenticated but not authorized. */
    public static final ProblemType AUTHORIZATION_DENIED =
            def("authorization-denied", "Authorization Denied", 403);

    /** 403 – Sensitive action requires step-up (MFA / two-person approval). */
    public static final ProblemType STEP_UP_REQUIRED =
            def("step-up-required", "Step-Up Required", 403);

    /** 401 – HMAC signature invalid or key revoked. */
    public static final ProblemType HMAC_SIGNATURE_INVALID =
            def("hmac-signature-invalid", "HMAC Signature Invalid", 401);

    /** 401 – JWT is malformed, expired, or fails verification. */
    public static final ProblemType JWT_INVALID =
            def("jwt-invalid", "JWT Invalid", 401);

    // -------------------------------------------------------------------------------------
    // Request, validation, contracts
    // -------------------------------------------------------------------------------------

    /** 400 – Semantic or structural validation errors on request payload. */
    public static final ProblemType VALIDATION_FAILED =
            def("validation-failed", "Validation Failed", 400);

    /** 415 – Unsupported content type. */
    public static final ProblemType UNSUPPORTED_MEDIA_TYPE =
            def("unsupported-media-type", "Unsupported Media Type", 415);

    /** 413 – Payload exceeds configured limits. */
    public static final ProblemType PAYLOAD_TOO_LARGE =
            def("payload-too-large", "Payload Too Large", 413);

    /** 422 – Schema/contract validation failed (OpenAPI/AsyncAPI). */
    public static final ProblemType SCHEMA_VALIDATION_FAILED =
            def("schema-validation-failed", "Schema Validation Failed", 422);

    /** 410 – Endpoint or contract version has reached Sunset. */
    public static final ProblemType ENDPOINT_SUNSET =
            def("endpoint-sunset", "Endpoint Sunset", 410);

    // -------------------------------------------------------------------------------------
    // Consistency, idempotency, concurrency
    // -------------------------------------------------------------------------------------

    /** 412 – If-Consistent-With did not match current entity version. */
    public static final ProblemType CONSISTENCY_PRECONDITION_FAILED =
            def("consistency-precondition-failed", "Consistency Precondition Failed", 412);

    /** 428 – Request requires a consistency token (If-Consistent-With). */
    public static final ProblemType CONSISTENCY_TOKEN_REQUIRED =
            def("consistency-token-required", "Consistency Token Required", 428);

    /** 409 – The provided Idempotency-Key conflicts with a different request hash. */
    public static final ProblemType IDEMPOTENCY_KEY_CONFLICT =
            def("idempotency-key-conflict", "Idempotency Key Conflict", 409);

    /** 409 – A replayed request was rejected by the idempotency store rules. */
    public static final ProblemType IDEMPOTENCY_REPLAY_REJECTED =
            def("idempotency-replay-rejected", "Idempotency Replay Rejected", 409);

    /** 404 – Resource not found under the current tenant. */
    public static final ProblemType RESOURCE_NOT_FOUND =
            def("resource-not-found", "Resource Not Found", 404);

    /** 409 – Update conflicts (optimistic locking / concurrent modification). */
    public static final ProblemType CONFLICT =
            def("conflict", "Conflict", 409);

    /** 409 – Serialization/deadlock while in serializable section; caller may retry. */
    public static final ProblemType TRANSACTION_SERIALIZATION_FAILURE =
            def("transaction-serialization-failure", "Transaction Serialization Failure", 409);

    /** 503 – Transaction timed out under contention; suggest retry with backoff+jitter. */
    public static final ProblemType TRANSACTION_TIMEOUT =
            def("transaction-timeout", "Transaction Timeout", 503);

    // -------------------------------------------------------------------------------------
    // Rate limits, quotas, capacity
    // -------------------------------------------------------------------------------------

    /** 429 – Per-tenant or per-principal rate limit exceeded. */
    public static final ProblemType RATE_LIMITED =
            def("rate-limited", "Rate Limited", 429);

    /** 429 – Quota exceeded (e.g., storage/search/requests). */
    public static final ProblemType QUOTA_EXCEEDED =
            def("quota-exceeded", "Quota Exceeded", 429);

    // -------------------------------------------------------------------------------------
    // Downstream / platform dependencies
    // -------------------------------------------------------------------------------------

    /** 503 – Critical dependency is unavailable (DB, cache, search, etc.). */
    public static final ProblemType DEPENDENCY_UNAVAILABLE =
            def("dependency-unavailable", "Dependency Unavailable", 503);

    /** 504 – Downstream timed out (payment/search/webhook destination). */
    public static final ProblemType DEPENDENCY_TIMEOUT =
            def("dependency-timeout", "Dependency Timeout", 504);

    /** 503 – Search index is lagging beyond SLO; OLTP fallback may be in effect. */
    public static final ProblemType SEARCH_INDEX_STALE =
            def("search-index-stale", "Search Index Stale", 503);

    // -------------------------------------------------------------------------------------
    // Payments & webhooks (PCI SAQ-A)
    // -------------------------------------------------------------------------------------

    /** 402 – Strong Customer Authentication is required to proceed. */
    public static final ProblemType PAYMENT_SCA_REQUIRED =
            def("payment-sca-required", "Payment SCA Required", 402);

    /** 402 – Authorization declined by payment provider. */
    public static final ProblemType PAYMENT_AUTH_DECLINED =
            def("payment-authorization-declined", "Payment Authorization Declined", 402);

    /** 502 – Capture/settlement failed after authorization. */
    public static final ProblemType PAYMENT_CAPTURE_FAILED =
            def("payment-capture-failed", "Payment Capture Failed", 502);

    /** 401 – Webhook signature invalid / source not trusted. */
    public static final ProblemType WEBHOOK_SIGNATURE_INVALID =
            def("webhook-signature-invalid", "Webhook Signature Invalid", 401);

    /** 409 – Webhook replay detected outside the allowed window. */
    public static final ProblemType WEBHOOK_REPLAY_DETECTED =
            def("webhook-replay-detected", "Webhook Replay Detected", 409);

    // -------------------------------------------------------------------------------------
    // Generic server-side
    // -------------------------------------------------------------------------------------

    /** 500 – Illegal state or unexpected server error. */
    public static final ProblemType INTERNAL_ERROR =
            def("internal-error", "Internal Error", 500);

    // -------------------------------------------------------------------------------------
    // Static registry & helpers
    // -------------------------------------------------------------------------------------

    static {
        Map<String, ProblemType> map = new LinkedHashMap<>();
        for (ProblemType t : new ProblemType[] {
                TENANT_REQUIRED, TENANT_UNKNOWN, TENANT_MISMATCH,
                AUTHENTICATION_FAILED, AUTHORIZATION_DENIED, STEP_UP_REQUIRED,
                HMAC_SIGNATURE_INVALID, JWT_INVALID,
                VALIDATION_FAILED, UNSUPPORTED_MEDIA_TYPE, PAYLOAD_TOO_LARGE,
                SCHEMA_VALIDATION_FAILED, ENDPOINT_SUNSET,
                CONSISTENCY_PRECONDITION_FAILED, CONSISTENCY_TOKEN_REQUIRED,
                IDEMPOTENCY_KEY_CONFLICT, IDEMPOTENCY_REPLAY_REJECTED,
                RESOURCE_NOT_FOUND, CONFLICT, TRANSACTION_SERIALIZATION_FAILURE, TRANSACTION_TIMEOUT,
                RATE_LIMITED, QUOTA_EXCEEDED,
                DEPENDENCY_UNAVAILABLE, DEPENDENCY_TIMEOUT, SEARCH_INDEX_STALE,
                PAYMENT_SCA_REQUIRED, PAYMENT_AUTH_DECLINED, PAYMENT_CAPTURE_FAILED,
                WEBHOOK_SIGNATURE_INVALID, WEBHOOK_REPLAY_DETECTED,
                INTERNAL_ERROR
        }) {
            map.put(t.slug(), t);
        }
        REGISTRY = Collections.unmodifiableMap(map);
    }

    private ProblemTypes() {
        /* no instances */
    }

    /**
     * Create a {@link ProblemType} for a custom slug without registering it globally.
     * Use for domain-specific, one-off errors until promoted to a shared type.
     */
    public static ProblemType custom(String slug, String title, int defaultStatus) {
        return create(slug, title, defaultStatus);
    }

    /** Resolve a registered type by slug (e.g., "validation-failed"). */
    public static Optional<ProblemType> bySlug(String slug) {
        if (slug == null) return Optional.empty();
        return Optional.ofNullable(REGISTRY.get(slug));
    }

    /** @return an unmodifiable view of the registered types keyed by slug. */
    public static Map<String, ProblemType> registry() {
        return REGISTRY;
    }

    /** Compose the canonical type URI for a given valid slug. */
    public static URI typeUri(String slug) {
        return URI.create(BASE + "/" + validateSlug(slug));
    }

    // -------------------------------------------------------------------------------------
    // Internal factories/validators
    // -------------------------------------------------------------------------------------

    private static ProblemType def(String slug, String title, int status) {
        return create(slug, title, status);
    }

    private static ProblemType create(String slug, String title, int status) {
        String s = validateSlug(slug);
        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException("title must not be blank");
        }
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("defaultStatus must be a valid HTTP status code");
        }
        return new ProblemType(s, typeUri(s), title.trim(), status);
    }

    private static String validateSlug(String slug) {
        if (slug == null || slug.isBlank()) {
            throw new IllegalArgumentException("slug must not be blank");
        }
        String s = slug.trim();
        if (!s.matches("[a-z0-9]+(?:-[a-z0-9]+)*")) {
            throw new IllegalArgumentException("slug must be lower-kebab-case [a-z0-9-], got: " + slug);
        }
        if (s.length() > 80) {
            throw new IllegalArgumentException("slug too long (max 80 chars)");
        }
        return s;
    }

    // -------------------------------------------------------------------------------------
    // Type
    // -------------------------------------------------------------------------------------

    /**
     * Immutable descriptor of a problem type.
     *
     * @param slug           lower-kebab-case short code (e.g., {@code validation-failed})
     * @param uri            stable absolute URI under {@link #BASE}
     * @param title          short, human-readable title (sentence case)
     * @param defaultStatus  suggested HTTP status code
     */
    public record ProblemType(String slug, URI uri, String title, int defaultStatus) {
        public ProblemType {
            Objects.requireNonNull(slug, "slug");
            Objects.requireNonNull(uri, "uri");
            Objects.requireNonNull(title, "title");
        }

        @Override
        public String toString() {
            return slug + " (" + defaultStatus + " → " + uri + ")";
        }
    }
}
