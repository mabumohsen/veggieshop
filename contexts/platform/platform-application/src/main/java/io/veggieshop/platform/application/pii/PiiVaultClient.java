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
 * Design goals:
 * - No PII in logs/traces/metrics
 * - ABAC enforcement upstream
 * - Read-your-writes via ReadYourWritesGuard
 * - Bounded retries with jitter for transient faults
 * - Tenant isolation + retention guardrails
 *
 * NOTE: لا يعتمد على Spring. إدارة المعاملات تكون داخل المنفذ (adapter) في طبقة infrastructure.
 */
public class PiiVaultClient {

    private static final Logger log = LoggerFactory.getLogger(PiiVaultClient.class);

    private static final Duration MIN_RETENTION = Duration.ofDays(1);
    private static final Duration MAX_RETENTION = Duration.ofDays(365L * 7);

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

    /** Resolve (decrypt and return) PII by handle with monotonic read semantics. */
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
            // يتطلب ReadYourWritesGuard أن يوفّر monotonic(Supplier<Optional<T>>)
            return readYourWrites.monotonic(() -> port.read(tenantId, ref));
        } catch (RuntimeException e) {
            span.recordException(e).setStatus(StatusCode.ERROR);
            throw e;
        } finally {
            span.end();
        }
    }

    /** Redact selected fields; storage is expected to version the document. */
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

    /** Rotate encryption keys for the referenced PII payload. */
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

    /** Delete (soft or hard) according to data-governance rules. */
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

    /** Fetch current handle (ref + version) without exposing payload. */
    public PiiHandle currentHandle(@NotNull TenantId tenantId, @NotNull String ref) {
        return port.currentHandle(tenantId, ref);
    }

    // ---------- Helpers ----------

    private void authorize(TenantId tenantId, PiiAction action, RiskLevel risk) {
        abac.require(tenantId, "PII_VAULT", action.name(), risk);
    }

    private Duration clampRetention(@Nullable Duration requested) {
        if (requested == null) return null;
        if (requested.compareTo(MIN_RETENTION) < 0) return MIN_RETENTION;
        if (requested.compareTo(MAX_RETENTION) > 0) return MAX_RETENTION;
        return requested;
    }

    private String safeTenant(TenantId tenantId) {
        return tenantId.value();
    }

    /** Generic bounded retry with small jitter. Adapter يُستحسن أن يرمي RuntimeException للعيوب الدائمة. */
    private <T> T withRetry(String opName, Supplier<T> supplier) {
        final int maxAttempts = 3;
        int attempt = 0;
        while (true) {
            attempt++;
            try {
                return supplier.get();
            } catch (RuntimeException e) {
                if (attempt >= maxAttempts) {
                    log.warn("PII op '{}' failed after {} attempts. Escalating.", opName, attempt);
                    throw e;
                }
                long base = (long) Math.pow(2, attempt - 1) * 25L; // 25, 50, 100
                long jitter = ThreadLocalRandom.current().nextLong(10, 30);
                long sleepMs = Math.min(base + jitter, 250L);
                sleepQuietly(sleepMs);
            }
        }
    }

    private void sleepQuietly(long millis) {
        try { Thread.sleep(millis); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
    }

    // ---------- Types & Port ----------

    public record PiiHandle(@NotNull String ref, long version) {
        public PiiHandle {
            if (ref == null || ref.isBlank()) throw new IllegalArgumentException("ref must not be blank");
            if (version < 0) throw new IllegalArgumentException("version must be >= 0");
        }
    }

    public interface PiiVaultPort {
        PiiHandle upsert(@NotNull TenantId tenantId,
                         @NotBlank String subjectType,
                         @NotBlank String subjectId,
                         @NotNull Map<String, String> pii,
                         @Nullable Duration retention,
                         @Nullable Map<String, String> tags,
                         @Nullable String idempotencyKey);

        Optional<Map<String, String>> read(@NotNull TenantId tenantId, @NotBlank String ref);

        PiiHandle redactFields(@NotNull TenantId tenantId, @NotBlank String ref, @NotNull Set<String> fieldsToRemove);

        PiiHandle rotate(@NotNull TenantId tenantId, @NotBlank String ref);

        boolean delete(@NotNull TenantId tenantId, @NotBlank String ref, boolean hardDelete);

        PiiHandle currentHandle(@NotNull TenantId tenantId, @NotBlank String ref);
    }

    public enum PiiAction { READ, WRITE, REDACT, ROTATE, DELETE, HARD_DELETE }
}
