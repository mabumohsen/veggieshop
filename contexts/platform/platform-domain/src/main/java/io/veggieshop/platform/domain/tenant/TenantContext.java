package io.veggieshop.platform.domain.tenant;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import org.slf4j.MDC;

/**
 * Enterprise-grade tenant context holder (Virtual Threads safe).
 *
 * <p>- Pure domain; no Spring dependencies. <br>
 * - Mirrors the active tenant to MDC ("tenantId") for JSON logs. <br>
 * - Deterministic scope restoration (no context bleed).
 */
public final class TenantContext {

  /** Canonical inbound header (kept in sync across HTTP/adapters). */
  public static final String REQUEST_HEADER = "X-Tenant-Id";

  /** MDC key for logs (must align with logging config). */
  public static final String MDC_TENANT_ID = "tenantId";

  private static final ThreadLocal<TenantId> TL_TENANT = new ThreadLocal<>();

  private TenantContext() {}

  // ---------------- Scoping ----------------

  /**
   * Opens a tenant scope and switches MDC accordingly.
   *
   * <p>Call {@link Scope#close()} in a finally block to restore the previous context.
   *
   * @param tenantId the tenant to activate
   * @return a {@link Scope} that restores the previous tenant/MDC on close
   * @throws NullPointerException if {@code tenantId} is null
   */
  public static Scope open(TenantId tenantId) {
    Objects.requireNonNull(tenantId, "tenantId");
    final TenantId prev = TL_TENANT.get();
    final String prevMdc = MDC.get(MDC_TENANT_ID);

    TL_TENANT.set(tenantId);
    MDC.put(MDC_TENANT_ID, tenantId.value());
    return new Scope(prev, prevMdc);
  }

  /**
   * Executes a {@link Runnable} within the given tenant scope.
   *
   * @param tenantId tenant to activate
   * @param runnable code to run
   * @throws NullPointerException if any argument is null
   */
  public static void within(TenantId tenantId, Runnable runnable) {
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(runnable, "runnable");
    final Scope scope = open(tenantId);
    try {
      runnable.run();
    } finally {
      scope.close();
    }
  }

  /**
   * Executes a {@link Supplier} within the given tenant scope and returns its result.
   *
   * @param <T> result type
   * @param tenantId tenant to activate
   * @param supplier code to run
   * @return supplier result
   * @throws NullPointerException if any argument is null
   */
  public static <T> T within(TenantId tenantId, Supplier<T> supplier) {
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(supplier, "supplier");
    final Scope scope = open(tenantId);
    try {
      return supplier.get();
    } finally {
      scope.close();
    }
  }

  // ---------------- Accessors ----------------

  /**
   * Returns the current tenant id, if present.
   *
   * @return optional tenant id
   */
  public static Optional<TenantId> currentTenantId() {
    return Optional.ofNullable(TL_TENANT.get());
  }

  /**
   * Returns the current tenant id or throws if absent.
   *
   * @return current tenant id
   * @throws IllegalStateException if no tenant is set
   */
  public static TenantId requireTenantId() {
    TenantId id = TL_TENANT.get();
    if (id == null) {
      throw new IllegalStateException("TenantId is required but not present in TenantContext");
    }
    return id;
  }

  /**
   * Returns whether a tenant is currently set in this thread.
   *
   * @return true if a tenant is currently set in this thread
   */
  public static boolean isPresent() {
    return TL_TENANT.get() != null;
  }

  /** Clears the current tenant from ThreadLocal and removes MDC entry. */
  public static void clear() {
    TL_TENANT.remove();
    MDC.remove(MDC_TENANT_ID);
  }

  // ---------------- Cross-thread helpers ----------------

  /**
   * Wraps a {@link Runnable} to capture and restore the tenant context across threads.
   *
   * @param delegate runnable to wrap
   * @return wrapped runnable that runs with the captured tenant context; returns the original
   *     runnable if no tenant is set
   * @throws NullPointerException if {@code delegate} is null
   */
  public static Runnable wrap(Runnable delegate) {
    Objects.requireNonNull(delegate, "delegate");
    final TenantId captured = TL_TENANT.get();
    if (captured == null) {
      return delegate;
    }
    return () -> {
      final Scope scope = open(captured);
      try {
        delegate.run();
      } finally {
        scope.close();
      }
    };
  }

  /**
   * Wraps a {@link Callable} to capture and restore the tenant context across threads.
   *
   * @param <V> return type
   * @param delegate callable to wrap
   * @return wrapped callable that runs with the captured tenant context; returns the original
   *     callable if no tenant is set
   * @throws NullPointerException if {@code delegate} is null
   */
  public static <V> Callable<V> wrap(Callable<V> delegate) {
    Objects.requireNonNull(delegate, "delegate");
    final TenantId captured = TL_TENANT.get();
    if (captured == null) {
      return delegate;
    }
    return () -> {
      final Scope scope = open(captured);
      try {
        return delegate.call();
      } finally {
        scope.close();
      }
    };
  }

  // ---------------- Scope ----------------

  /**
   * Disposable scope that restores the previous ThreadLocal/MDC tenant on close.
   *
   * <p>Instances are created by {@link TenantContext#open(TenantId)}.
   */
  public static final class Scope implements AutoCloseable, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final TenantId previousTenant;
    private final String previousMdc;

    private Scope(TenantId previousTenant, String previousMdc) {
      this.previousTenant = previousTenant;
      this.previousMdc = previousMdc;
    }

    /** Restores the previous tenant context and MDC value. */
    @Override
    public void close() {
      if (previousTenant == null) {
        TL_TENANT.remove();
      } else {
        TL_TENANT.set(previousTenant);
      }

      if (previousMdc == null) {
        MDC.remove(MDC_TENANT_ID);
      } else {
        MDC.put(MDC_TENANT_ID, previousMdc);
      }
    }
  }
}
