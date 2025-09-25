package io.veggieshop.platform.domain.tenant;

import org.slf4j.MDC;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Enterprise-grade tenant context holder (Virtual Threads safe).
 * - Pure domain; no Spring dependencies.
 * - Mirrors the active tenant to MDC ("tenantId") for JSON logs.
 * - Deterministic scope restoration (no context bleed).
 */
public final class TenantContext {

    /** Canonical inbound header (kept in sync across HTTP/adapters). */
    public static final String REQUEST_HEADER = "X-Tenant-Id";

    /** MDC key for logs (must align with logging config). */
    public static final String MDC_TENANT_ID = "tenantId";

    private static final ThreadLocal<TenantId> TL_TENANT = new ThreadLocal<>();

    private TenantContext() { }

    // ---------------- Scoping ----------------

    public static Scope open(TenantId tenantId) {
        Objects.requireNonNull(tenantId, "tenantId");
        final TenantId prev = TL_TENANT.get();
        final String prevMdc = MDC.get(MDC_TENANT_ID);

        TL_TENANT.set(tenantId);
        MDC.put(MDC_TENANT_ID, tenantId.value());
        return new Scope(prev, prevMdc);
    }

    public static void within(TenantId tenantId, Runnable runnable) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(runnable, "runnable");
        try (var ignored = open(tenantId)) {
            runnable.run();
        }
    }

    public static <T> T within(TenantId tenantId, Supplier<T> supplier) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(supplier, "supplier");
        try (var ignored = open(tenantId)) {
            return supplier.get();
        }
    }

    // ---------------- Accessors ----------------

    public static Optional<TenantId> currentTenantId() {
        return Optional.ofNullable(TL_TENANT.get());
    }

    public static TenantId requireTenantId() {
        TenantId id = TL_TENANT.get();
        if (id == null) {
            throw new IllegalStateException("TenantId is required but not present in TenantContext");
        }
        return id;
    }

    public static boolean isPresent() {
        return TL_TENANT.get() != null;
    }

    public static void clear() {
        TL_TENANT.remove();
        MDC.remove(MDC_TENANT_ID);
    }

    // ---------------- Cross-thread helpers ----------------

    public static Runnable wrap(Runnable delegate) {
        Objects.requireNonNull(delegate, "delegate");
        final TenantId captured = TL_TENANT.get();
        if (captured == null) return delegate;
        return () -> {
            try (var ignored = open(captured)) {
                delegate.run();
            }
        };
    }

    public static <V> Callable<V> wrap(Callable<V> delegate) {
        Objects.requireNonNull(delegate, "delegate");
        final TenantId captured = TL_TENANT.get();
        if (captured == null) return delegate;
        return () -> {
            try (var ignored = open(captured)) {
                return delegate.call();
            }
        };
    }

    // ---------------- Scope ----------------

    public static final class Scope implements AutoCloseable, Serializable {
        @Serial private static final long serialVersionUID = 1L;

        private final TenantId previousTenant;
        private final String previousMdc;

        private Scope(TenantId previousTenant, String previousMdc) {
            this.previousTenant = previousTenant;
            this.previousMdc = previousMdc;
        }

        @Override
        public void close() {
            if (previousTenant == null) TL_TENANT.remove();
            else TL_TENANT.set(previousTenant);

            if (previousMdc == null) MDC.remove(MDC_TENANT_ID);
            else MDC.put(MDC_TENANT_ID, previousMdc);
        }
    }
}
