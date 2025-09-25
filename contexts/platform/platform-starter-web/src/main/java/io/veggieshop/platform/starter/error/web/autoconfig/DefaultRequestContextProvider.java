package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import io.veggieshop.problem.core.RequestContext;
import org.slf4j.MDC;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Map;

public final class DefaultRequestContextProvider implements RequestContextProvider {

    // اختياري: حقن خصائص إن لزم
    public DefaultRequestContextProvider() {}

    @SuppressWarnings("unchecked")
    @Override
    public RequestContext from(HttpServletRequest req) {
        String method = req.getMethod();
        String path = safe(req.getRequestURI());

        String tenant = TenantContext.currentTenantId().map(TenantId::value).orElse(null);
        if (tenant == null) tenant = MDC.get(TenantContext.MDC_TENANT_ID);

        // تأكد أن مفاتيح MDC متوافقة مع LogJsonConfig لديك
        String traceId = firstNonBlank(MDC.get("traceId"), MDC.get("trace_id"));
        String spanId  = firstNonBlank(MDC.get("spanId"), MDC.get("span_id"));

        String requestId     = firstNonBlank(MDC.get("requestId"), header(req, "X-Request-Id"));
        String correlationId = firstNonBlank(MDC.get("correlationId"), header(req, "X-Correlation-Id"));

        int headerCount;
        int paramCount;

        Map<String, ?> safeHeaders = (Map<String, ?>) req.getAttribute("pii.sanitized.headers");
        Map<String, ?> safeParams  = (Map<String, ?>) req.getAttribute("pii.sanitized.params");

        if (safeHeaders != null) {
            headerCount = safeHeaders.size();
        } else {
            headerCount = 0;
            Enumeration<String> hn = req.getHeaderNames();
            while (hn != null && hn.hasMoreElements()) { hn.nextElement(); headerCount++; }
        }
        paramCount = (safeParams != null) ? safeParams.size() : req.getParameterMap().size();

        long ts = System.currentTimeMillis();

        return new RequestContext(method, path, tenant, traceId, spanId, requestId, correlationId, headerCount, paramCount, ts);
    }

    private static String header(HttpServletRequest req, String name) {
        String v = req.getHeader(name);
        return (v == null || v.isBlank()) ? null : v;
    }
    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return null;
    }
    private static String safe(String s) { return (s == null || s.isBlank()) ? "/" : s; }
}
