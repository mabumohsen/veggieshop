package io.veggieshop.platform.application.pii;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.veggieshop.platform.application.consistency.ReadYourWritesGuard;
import io.veggieshop.platform.application.security.AbacPolicyEngine;
import io.veggieshop.platform.domain.security.RiskLevel;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

/**
 * Strongly-typed PII Vault client orchestrating access policies, monotonic reads, retries and observability.
 *
 * <p><b>Design goals (per PRD 2.0):</b>
 * <ul>
 *   <li><b>No PII in logs, traces, or metrics.</b> Only structural/hardening attributes are emitted.</li>
 *   <li><b>ABAC enforcement</b> with optional step-up handled upstream; this client calls {@link AbacPolicyEngine} to gate access.</li>
 *   <li><b>Read-your-writes</b> via {@link ReadYourWritesGuard} on fetch paths.</li>
 *   <li><b>Bounded retries with jitter</b> for transient storage faults (deadlocks, timeouts).</li>
 *   <li><b>Tenant isolation</b>: every operation is scoped to {@link TenantId}.</li>
 *   <li><b>Retention-aware</b> operations: retention bounds are validated before write.</li>
 * </ul>
 *
 * <p>This class is intentionally opinionated and depends on a storage <i>port</i> ({@link PiiVaultPort})
 * implemented in infrastructure (e.g., JDBC adapter with field-level encryption and RLS).
 *
 * <p><b>IMPORTANT:</b> Never log PII maps or field values here. If you must inspect data during debugging,
 * do it in a secure environment and ensure redaction before any logging.</p>
 */
@Service
public class PiiVaultClient {

    private static final Logger log = LoggerFactory.getLogger(PiiVaultClient.class);

    // Retention guardrails (consider externalizing via @ConfigurationProperties if you need runtime tuning).
    private static final Duration MIN_RETENTION = Duration.ofDays(1);
    private static final Duration MAX_RETENTION = Duration.ofYears(7);

    private final PiiVaultPort port;
    private final AbacPolicyEngine abac;
    private final ReadYourWritesGuard readYourWrites;
    private final Tracer tracer;
    private final Clock clock;

    public PiiVaultClient(
            PiiVaultPort port,
            AbacPolicyEngine abac,
            ReadYourWritesGuard readYourWrites,
            Tracer tracer,
            Clock clock
    ) {
        this.port = Objects.requireNonNull(port, "port");
        this.abac = Objects.requireNonNull(abac, "abac");
        this.readYourWrites = Objects.requireNonNull(readYourWrites, "readYourWrites");
        this.tracer = Objects.requireNonNull(tracer, "tracer");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Create or update PII for a subject. Storage must guarantee encryption-at-rest and RLS by tenant.
     *
     * @param tenantId       tenant scope (required)
     * @param subjectType    logical owner namespace (e.g., "customer", "vendor") - not PII
     * @param subjectId      subject identifier (opaque business id) - not PII content
     * @param pii            map of PII fields (VALUES MUST NOT BE LOGGED)
     * @param retention      desired retention; clamped to guardrails; {@code null} to use storage default
     * @param tags           optional non-PII tags (e.g., "source":"signup")
     * @param idempotencyKey optional idempotency key to ensure exactly-once effect
     * @param risk           declared risk level of this operation (used by ABAC)
     * @return handle containing opaque reference and current version
     */
    @Transactional
    public PiiHandle upsert(
            @NotNull TenantId tenantId,
            @NotBlank String subjectType,
            @NotBlank String subjectId,
            @NotNull Map<String, String> pii,
            @Nullable Duration retention,
            @Nullable Map<String, String> tags,
            @Nullable String idempotencyKey,
            @NotNull RiskLevel risk
    ) {
        authorize(tenantId, PiiAction.WRITE, risk);
        final var clampedRetention = clampRetention(retention);
        final Span span = tracer.spanBuilder("pii.upsert").startSpan();
        span.setAttribute("tenant.id", safeTenant(tenantId));
        span.setAttribute("pii.subject.type", subjectType);
        span.setAttribute("pii.tags.count", tags == null ? 0 : tags.size());
        span.setAttribute("pii.fields.count", pii.size());
        try {
            return withRetry("pii.upsert", () ->
                    port.upsert(tenantId, subjectType, subjectId, pii, clampedRetention, tags, idempotencyKey)
            );
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            span.end();
        }
    }

    /**
     * Resolve (decrypt and return) PII by handle. The result is never logged or traced.
     * RYW guards are applied to ensure monotonicity when a consistency token exists upstream.
     */
    @Transactional(readOnly = true)
    public Optional<Map<String, String>> resolve(
            @NotNull TenantId tenantId,
            @NotNull String ref,
            @NotNull RiskLevel risk
    ) {
        authorize(tenantId, PiiAction.READ, risk);
        final Span span = tracer.spanBuilder("pii.resolve").startSpan();
        span.setAttribute("tenant.id", safeTenant(tenantId));
        span.setAttribute("pii.ref.len", ref.length());
        try {
            return readYourWrites.monotonic(() -> port.read(tenantId, ref));
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            // Do NOT attach any PII to the span.
            span.end();
        }
    }

    /**
     * Redact selected fields from a PII record without removing the entire record.
     * Storage is expected to version the document and maintain auditability.
     */
    @Transactional
    public PiiHandle redact(
            @NotNull TenantId tenantId,
            @NotNull String ref,
            @NotNull Set<String> fieldsToRemove,
            @NotNull RiskLevel risk
    ) {
        authorize(tenantId, PiiAction.REDACT, risk);
        if (fieldsToRemove.isEmpty()) {
            return currentHandle(tenantId, ref);
        }
        final Span span = tracer.spanBuilder("pii.redact").startSpan();
        span.setAttribute("tenant.id", safeTenant(tenantId));
        span.setAttribute("pii.ref.len", ref.length());
        span.setAttribute("pii.redact.count", fieldsToRemove.size());
        try {
            return withRetry("pii.redact", () -> port.redactFields(tenantId, ref, fieldsToRemove));
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            span.end();
        }
    }

    /**
     * Rotate encryption keys for the referenced PII payload (re-encrypt-in-place semantics).
     */
    @Transactional
    public PiiHandle rotate(
            @NotNull TenantId tenantId,
            @NotNull String ref,
            @NotNull RiskLevel risk
    ) {
        authorize(tenantId, PiiAction.ROTATE, risk);
        final Span span = tracer.spanBuilder("pii.rotate").startSpan();
        span.setAttribute("tenant.id", safeTenant(tenantId));
        span.setAttribute("pii.ref.len", ref.length());
        try {
            return withRetry("pii.rotate", () -> port.rotate(tenantId, ref));
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            span.end();
        }
    }

    /**
     * Delete (soft or hard) a PII record according to data-governance rules.
     * <p>
     * - Soft delete: marks record as deleted but keeps tombstone for retention policy validation and replay fences.
     * - Hard delete: permanently wipes data (requires higher-risk permission).
     */
    @Transactional
    public boolean delete(
            @NotNull TenantId tenantId,
            @NotNull String ref,
            boolean hardDelete,
            @NotNull RiskLevel risk
    ) {
        authorize(tenantId, hardDelete ? PiiAction.HARD_DELETE : PiiAction.DELETE, risk);
        final Span span = tracer.spanBuilder("pii.delete").startSpan();
        span.setAttribute("tenant.id", safeTenant(tenantId));
        span.setAttribute("pii.ref.len", ref.length());
        span.setAttribute(AttributeKey.booleanKey("pii.delete.hard"), hardDelete);
        try {
            return withRetry("pii.delete", () -> port.delete(tenantId, ref, hardDelete));
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            span.end();
        }
    }

    /**
     * Fetch current handle (ref + version) without exposing payload.
     */
    @Transactional(readOnly = true)
    public PiiHandle currentHandle(@NotNull TenantId tenantId, @NotNull String ref) {
        return port.currentHandle(tenantId, ref);
    }

    // ---------- Helpers ----------

    private void authorize(TenantId tenantId, PiiAction action, RiskLevel risk) {
        // Defer to ABAC engine. The concrete API is domain-specific; "require" should throw if not allowed.
        // Resource type and action strings are kept stable for policy-as-code mappings.
        abac.require(
                tenantId,
                "PII_VAULT",
                action.name(),
                risk
        );
    }

    private Duration clampRetention(@Nullable Duration requested) {
        if (requested == null) return null; // storage default
        if (requested.compareTo(MIN_RETENTION) < 0) return MIN_RETENTION;
        if (requested.compareTo(MAX_RETENTION) > 0) return MAX_RETENTION;
        return requested;
    }

    private String safeTenant(TenantId tenantId) {
        // Expose only the public/opaque tenant identifier. Avoid any human-readable names in telemetry.
        return tenantId.value();
    }

    private <T> T withRetry(String opName, Supplier<T> supplier) {
        final int maxAttempts = 3;
        int attempt = 0;
        while (true) {
            attempt++;
            try {
                return supplier.get();
            } catch (DataAccessException | ConcurrencyFailureException e) {
                if (attempt >= maxAttempts) {
                    log.warn("PII op '{}' failed after {} attempts (transient). Escalating.", opName, attempt);
                    throw e;
                }
                // Exponential backoff with jitter; capped to 250ms.
                long base = (long) Math.pow(2, attempt - 1) * 25L;
                long jitter = ThreadLocalRandom.current().nextLong(10, 30);
                long sleepMs = Math.min(base + jitter, 250L);
                sleepQuietly(sleepMs);
            }
        }
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // ---------- Types & Port (Application-level contract) ----------

    /**
     * Opaque handle to a PII record in the vault (reference and optimistic version).
     * The reference MUST NOT encode any PII or tenant secrets; it is safe for storage in domain aggregates.
     */
    public record PiiHandle(@NotNull String ref, long version) {
        public PiiHandle {
            if (ref == null || ref.isBlank()) {
                throw new IllegalArgumentException("ref must not be blank");
            }
            if (version < 0) {
                throw new IllegalArgumentException("version must be >= 0");
            }
        }
    }

    /**
     * Application port for PII vault operations.
     * Implementations live in infrastructure (e.g., {@code PiiVaultJdbcAdapter}) and MUST enforce:
     * <ul>
     *   <li>Per-tenant schema or row-level security</li>
     *   <li>Field-level encryption at rest</li>
     *   <li>Auditability and versioning</li>
     *   <li>No PII leakage to logs/traces/metrics</li>
     * </ul>
     */
    public interface PiiVaultPort {
        PiiHandle upsert(
                @NotNull TenantId tenantId,
                @NotBlank String subjectType,
                @NotBlank String subjectId,
                @NotNull Map<String, String> pii,
                @Nullable Duration retention,
                @Nullable Map<String, String> tags,
                @Nullable String idempotencyKey
        );

        @Transactional(readOnly = true)
        Optional<Map<String, String>> read(@NotNull TenantId tenantId, @NotBlank String ref);

        PiiHandle redactFields(@NotNull TenantId tenantId, @NotBlank String ref, @NotNull Set<String> fieldsToRemove);

        PiiHandle rotate(@NotNull TenantId tenantId, @NotBlank String ref);

        boolean delete(@NotNull TenantId tenantId, @NotBlank String ref, boolean hardDelete);

        @Transactional(readOnly = true)
        PiiHandle currentHandle(@NotNull TenantId tenantId, @NotBlank String ref);
    }

    /**
     * Actions recognized by policies. Keep string names stable for policy-as-code (OPA/ABAC).
     */
    public enum PiiAction {
        READ, WRITE, REDACT, ROTATE, DELETE, HARD_DELETE
    }
}
