package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.application.consistency.ConsistencyService;
import io.veggieshop.platform.application.consistency.ReadYourWritesGuard;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Objects;
import java.util.Set;

/**
 * ConsistencyPreconditionInterceptor
 *
 * - يفتح نطاق طلب consistency (openRequest) اعتماداً على الهيدرز:
 *     If-Consistent-With, X-Consistency-Token
 * - يمرر If-Match (ETag precondition) كخاصية للطلب للطبقات اللاحقة.
 * - يفعّل Read-Your-Writes (RYW) قبل معالجات القراءة GET/HEAD.
 *
 * ملاحظة: لا يحمل stereotype؛ يقوم الـ starter بتسجيله وترتيبه.
 */
@Order(ConsistencyPreconditionInterceptor.ORDER)
public final class ConsistencyPreconditionInterceptor implements HandlerInterceptor {

    /** متأخر قليلاً قبل دخول الكنترولرات، بحيث تكون الخصائص متاحة للمعالجات/advices. */
    public static final int ORDER = Ordered.LOWEST_PRECEDENCE - 200;

    // ----- Canonical headers -----
    public static final String HDR_IF_CONSISTENT_WITH = "If-Consistent-With";
    public static final String HDR_CONSISTENCY_TOKEN  = "X-Consistency-Token";
    public static final String HDR_IF_MATCH           = "If-Match";
    public static final String HDR_TENANT_ID          = TenantContext.REQUEST_HEADER;

    // ----- Request attributes for downstream layers -----
    public static final String ATTR_SCOPE = ConsistencyPreconditionInterceptor.class.getName() + ".SCOPE";
    public static final String ATTR_IF_CONSISTENT_WITH =
            ConsistencyPreconditionInterceptor.class.getName() + ".IF_CONSISTENT_WITH";
    public static final String ATTR_IF_MATCH_RAW =
            ConsistencyPreconditionInterceptor.class.getName() + ".IF_MATCH_RAW";
    public static final String ATTR_RYW_DEADLINE_EPOCH_MS =
            ConsistencyPreconditionInterceptor.class.getName() + ".RYW_DEADLINE_MS";

    // ----- Bypass allowlist (صحة/داخلية) -----
    private static final Set<String> ALLOWLIST_PREFIXES = Set.of("/actuator", "/internal", "/_internal");
    private static final Set<String> ALLOWLIST_EXACT    = Set.of("/error", "/favicon.ico");

    private final ConsistencyService consistency;
    private final ReadYourWritesGuard rywGuard;

    public ConsistencyPreconditionInterceptor(ConsistencyService consistency,
                                              ReadYourWritesGuard rywGuard) {
        this.consistency = Objects.requireNonNull(consistency, "consistency");
        this.rywGuard    = Objects.requireNonNull(rywGuard, "rywGuard");
    }

    @Override
    public boolean preHandle(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Object handler
    ) {
        // CORS preflight + مسارات مسموحة
        if (shouldBypass(request)) {
            return true;
        }

        // استخرج/تحقق المستأجر: يجب أن يكون TenantFilter قد ثبّته
        TenantId tenant = TenantContext.currentTenantId().orElseGet(() -> {
            String fromHeader = firstHeaderValue(request.getHeader(HDR_TENANT_ID));
            if (fromHeader == null || fromHeader.isBlank()) {
                throw new IllegalStateException("Missing required header: " + HDR_TENANT_ID);
            }
            return TenantId.of(fromHeader.trim());
        });

        final String method = request.getMethod();
        final boolean isRead  = isSafeRead(method);
        final boolean isWrite = isMutating(method);

        // افتح نطاق الطلب في ConsistencyService (يُغلق في afterCompletion)
        final String ifConsistentWith = trimOrNull(request.getHeader(HDR_IF_CONSISTENT_WITH));
        final String priorToken       = trimOrNull(request.getHeader(HDR_CONSISTENCY_TOKEN));

        ConsistencyService.Scope scope =
                consistency.openRequest(tenant.value(), ifConsistentWith, priorToken);
        request.setAttribute(ATTR_SCOPE, scope);

        // مرّر دلالات القراءة/الانتظار (RYW) عند الحاجة
        if (isRead && ifConsistentWith != null) {
            request.setAttribute(ATTR_IF_CONSISTENT_WITH, ifConsistentWith);
            long deadlineMs = System.currentTimeMillis() + consistency.properties().rywMaxWait().toMillis();
            request.setAttribute(ATTR_RYW_DEADLINE_EPOCH_MS, deadlineMs);

            // انتظر watermark إن لزم (best-effort)
            rywGuard.awaitIfRequested();
        }

        // مرّر If-Match للكتابة (يتحقق لاحقاً في الخدمات/المعالج)
        if (isWrite) {
            final String ifMatch = trimOrNull(request.getHeader(HDR_IF_MATCH));
            if (ifMatch != null) {
                request.setAttribute(ATTR_IF_MATCH_RAW, ifMatch);
            }
        }

        return true;
    }

    @Override
    public void afterCompletion(@NonNull HttpServletRequest request,
                                @NonNull HttpServletResponse response,
                                @NonNull Object handler,
                                Exception ex) {
        // أغلق نطاق ConsistencyService إن وُجد
        Object s = request.getAttribute(ATTR_SCOPE);
        if (s instanceof ConsistencyService.Scope scope) {
            try {
                scope.close();
            } finally {
                request.removeAttribute(ATTR_SCOPE);
            }
        }
    }

    // --------------------------------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------------------------------
    private static boolean isSafeRead(String method) {
        return switch (method) { case "GET", "HEAD" -> true; default -> false; };
    }
    private static boolean isMutating(String method) {
        return switch (method) { case "POST", "PUT", "PATCH", "DELETE" -> true; default -> false; };
    }
    private static boolean shouldBypass(HttpServletRequest request) {
        // CORS preflight
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null) {
            return true;
        }
        String path = request.getRequestURI();
        if (path == null || path.isEmpty()) return false;
        if (ALLOWLIST_EXACT.contains(path)) return true;
        for (String p : ALLOWLIST_PREFIXES) if (path.startsWith(p)) return true;
        return false;
    }
    private static String firstHeaderValue(String raw) {
        if (raw == null) return null;
        int comma = raw.indexOf(',');
        return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
    }
    private static String trimOrNull(String s) { return (s == null) ? null : s.trim(); }
}
