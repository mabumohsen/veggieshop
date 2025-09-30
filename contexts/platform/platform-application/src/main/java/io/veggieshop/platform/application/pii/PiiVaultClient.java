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
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Strongly-typed PII Vault client orchestrating access policies, monotonic reads, retries and
 * observability.
 *
 * <p>Design goals:
 *
 * <ul>
 *   <li>No PII in logs/traces/metrics
 *   <li>ABAC enforcement upstream
 *   <li>Read-your-writes via {@link ReadYourWritesGuard}
 *   <li>Bounded retries with jitter for transient faults
 *   <li>Tenant isolation and retention guardrails
 * </ul>
 *
 * <p>Note: This class has no Spring dependency. Transaction management should be handled in the
 * adapter (infrastructure) layer.
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

  /**
   * Creates a new {@code PiiVaultClient}.
   *
   * @param port port to the vault adapter
   * @param abac ABAC policy engine used for authorization
   * @param readYourWrites guard that enforces read-your-writes semantics
   * @param tracer OpenTelemetry tracer for spans
   * @param clock time source for timing and retention calculations
   */
  public PiiVaultClient(
      PiiVaultPort port,
      AbacPolicyEngine abac,
      ReadYourWritesGuard readYourWrites,
      Tracer tracer,
      Clock clock) {
    this.port = Objects.requireNonNull(port, "port");
    this.abac = Objects.requireNonNull(abac, "abac");
    this.readYourWrites = Objects.requireNonNull(readYourWrites, "readYourWrites");
    this.tracer = Objects.requireNonNull(tracer, "tracer");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Inserts or updates a PII document and returns the new handle.
   *
   * @param tenantId tenant identifier
   * @param subjectType domain-specific subject type (e.g., "Customer")
   * @param subjectId domain-specific subject identifier
   * @param pii key/value PII payload (values are encrypted at rest)
   * @param retention requested retention window (will be clamped to a safe range)
   * @param tags optional non-PII tags for lookup/auditing
   * @param idempotencyKey optional key to deduplicate client retries
   * @param risk risk level used for ABAC policy
   * @return handle referencing the stored PII and its version
   */
  public PiiHandle upsert(
      @NotNull TenantId tenantId,
      @NotBlank String subjectType,
      @NotBlank String subjectId,
      @NotNull Map<String, String> pii,
      @Nullable Duration retention,
      @Nullable Map<String, String> tags,
      @Nullable String idempotencyKey,
      @NotNull RiskLevel risk) {
    authorize(tenantId, PiiAction.WRITE, risk);
    final var clampedRetention = clampRetention(retention);
    final Span span = tracer.spanBuilder("pii.upsert").startSpan();
    span.setAttribute("tenant.id", safeTenant(tenantId));
    span.setAttribute("pii.subject.type", subjectType);
    span.setAttribute("pii.tags.count", tags == null ? 0 : tags.size());
    span.setAttribute("pii.fields.count", pii.size());
    try {
      return withRetry(
          "pii.upsert",
          () ->
              port.upsert(
                  tenantId, subjectType, subjectId, pii, clampedRetention, tags, idempotencyKey));
    } catch (RuntimeException e) {
      span.recordException(e).setStatus(StatusCode.ERROR);
      throw e;
    } finally {
      span.end();
    }
  }

  /** Resolve (decrypt and return) PII by handle with monotonic read semantics. */
  public Optional<Map<String, String>> resolve(
      @NotNull TenantId tenantId, @NotNull String ref, @NotNull RiskLevel risk) {
    authorize(tenantId, PiiAction.READ, risk);
    final Span span = tracer.spanBuilder("pii.resolve").startSpan();
    span.setAttribute("tenant.id", safeTenant(tenantId));
    span.setAttribute("pii.ref.len", ref.length());
    try {
      // Use ReadYourWritesGuard to ensure we read at or after the client's required watermark.
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
      @NotNull RiskLevel risk) {
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
      @NotNull TenantId tenantId, @NotNull String ref, @NotNull RiskLevel risk) {
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
      @NotNull RiskLevel risk) {
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

  /**
   * Authorizes the given action for the tenant and risk level using the ABAC engine.
   *
   * @param tenantId tenant identifier
   * @param action PII action being requested
   * @param risk risk level for policy evaluation
   * @throws SecurityException if authorization fails (implementation-specific)
   */
  private void authorize(TenantId tenantId, PiiAction action, RiskLevel risk) {
    abac.require(tenantId, "PII_VAULT", action.name(), risk);
  }

  /**
   * Clamps the requested retention to the allowed range {@code [MIN_RETENTION, MAX_RETENTION]}.
   * Returns {@code null} unchanged to mean “no retention specified”.
   *
   * @param requested requested retention duration (nullable)
   * @return clamped duration or {@code null} if no retention was requested
   */
  private Duration clampRetention(@Nullable Duration requested) {
    if (requested == null) {
      return null;
    }
    if (requested.compareTo(MIN_RETENTION) < 0) {
      return MIN_RETENTION;
    }
    if (requested.compareTo(MAX_RETENTION) > 0) {
      return MAX_RETENTION;
    }
    return requested;
  }

  /**
   * Returns a safe, non-PII tenant identifier suitable for traces/logs/metrics.
   *
   * @param tenantId tenant identifier
   * @return a stable string that does not expose PII
   */
  private String safeTenant(TenantId tenantId) {
    return tenantId.value();
  }

  /**
   * Generic bounded retry with small jitter.
   *
   * <p>Adapters should throw {@link RuntimeException} for permanent failures.
   */
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

  /**
   * Sleeps for the given number of milliseconds, restoring the interrupt status if interrupted.
   *
   * @param millis number of milliseconds to sleep
   */
  private void sleepQuietly(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
    }
  }

  // ---------- Types & Port ----------

  /**
   * Opaque handle referencing a PII record and its version.
   *
   * @param ref stable reference string
   * @param version monotonic version number (non-negative)
   */
  public record PiiHandle(@NotNull String ref, long version) {
    /**
     * Canonical compact constructor that validates invariants.
     *
     * @throws IllegalArgumentException if {@code ref} is blank or {@code version} is negative
     */
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
   * Port (SPI) that abstracts the underlying PII vault implementation.
   *
   * <p>Implementations must enforce tenant isolation and avoid logging PII.
   */
  public interface PiiVaultPort {
    /**
     * Creates or updates a PII record for the given subject.
     *
     * @param tenantId tenant identifier
     * @param subjectType domain-specific subject type (e.g., "Customer")
     * @param subjectId domain-specific subject identifier
     * @param pii key/value PII payload; values must be handled securely
     * @param retention requested retention window (may be {@code null})
     * @param tags optional non-PII tags for lookup/auditing
     * @param idempotencyKey optional key to deduplicate client retries
     * @return handle referencing the stored PII and its version
     */
    PiiHandle upsert(
        @NotNull TenantId tenantId,
        @NotBlank String subjectType,
        @NotBlank String subjectId,
        @NotNull Map<String, String> pii,
        @Nullable Duration retention,
        @Nullable Map<String, String> tags,
        @Nullable String idempotencyKey);

    /**
     * Reads and decrypts a PII record by reference.
     *
     * @param tenantId tenant identifier
     * @param ref opaque reference returned by this vault
     * @return decrypted fields if present; otherwise {@code Optional.empty()}
     */
    Optional<Map<String, String>> read(@NotNull TenantId tenantId, @NotBlank String ref);

    /**
     * Redacts (removes) the specified fields from the referenced PII record.
     *
     * @param tenantId tenant identifier
     * @param ref opaque reference
     * @param fieldsToRemove set of field names to remove
     * @return new handle for the updated (re-versioned) record
     */
    PiiHandle redactFields(
        @NotNull TenantId tenantId, @NotBlank String ref, @NotNull Set<String> fieldsToRemove);

    /**
     * Rotates encryption keys for the referenced PII record.
     *
     * @param tenantId tenant identifier
     * @param ref opaque reference
     * @return new handle for the re-encrypted (re-versioned) record
     */
    PiiHandle rotate(@NotNull TenantId tenantId, @NotBlank String ref);

    /**
     * Deletes a PII record according to governance rules.
     *
     * @param tenantId tenant identifier
     * @param ref opaque reference
     * @param hardDelete if {@code true}, perform irreversible deletion
     * @return {@code true} if a record was deleted; otherwise {@code false}
     */
    boolean delete(@NotNull TenantId tenantId, @NotBlank String ref, boolean hardDelete);

    /**
     * Returns the current handle (reference and version) without exposing payload.
     *
     * @param tenantId tenant identifier
     * @param ref opaque reference
     * @return current handle for the referenced record
     */
    PiiHandle currentHandle(@NotNull TenantId tenantId, @NotBlank String ref);
  }

  /** Allowed PII operations for ABAC checks and audit. */
  public enum PiiAction {
    READ,
    WRITE,
    REDACT,
    ROTATE,
    DELETE,
    HARD_DELETE
  }
}
