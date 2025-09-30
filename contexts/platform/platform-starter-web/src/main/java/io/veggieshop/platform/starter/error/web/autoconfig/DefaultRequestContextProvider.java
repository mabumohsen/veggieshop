package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import io.veggieshop.problem.core.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Map;
import org.slf4j.MDC;

/**
 * Default adapter that builds a {@link RequestContext} from the current HTTP request. Pulls
 * identifiers from headers and MDC; avoids PII.
 */
public final class DefaultRequestContextProvider implements RequestContextProvider {

  /** No-op constructor for frameworks. */
  public DefaultRequestContextProvider() {}

  @Override
  public RequestContext from(HttpServletRequest req) {
    // Resolve tenant from context or MDC
    String tenant = TenantContext.currentTenantId().map(TenantId::value).orElse(null);
    if (tenant == null) {
      tenant = MDC.get(TenantContext.MDC_TENANT_ID);
    }

    // Common IDs (match your logging/MDC conventions)
    String traceId = firstNonBlank(MDC.get("traceId"), MDC.get("trace_id"));
    String spanId = firstNonBlank(MDC.get("spanId"), MDC.get("span_id"));
    String requestId = firstNonBlank(MDC.get("requestId"), header(req, "X-Request-Id"));
    String correlationId = firstNonBlank(MDC.get("correlationId"), header(req, "X-Correlation-Id"));

    // Safe counts from sanitized attributes if present
    Map<?, ?> safeHeaders = (Map<?, ?>) req.getAttribute("pii.sanitized.headers");
    Map<?, ?> safeParams = (Map<?, ?>) req.getAttribute("pii.sanitized.params");

    int headerCount;
    if (safeHeaders != null) {
      headerCount = safeHeaders.size();
    } else {
      headerCount = 0;
      Enumeration<String> hn = req.getHeaderNames();
      while (hn != null && hn.hasMoreElements()) {
        hn.nextElement();
        headerCount++;
      }
    }
    int paramCount = (safeParams != null) ? safeParams.size() : req.getParameterMap().size();

    final String method = req.getMethod();
    final String path = safe(req.getRequestURI());
    final long ts = System.currentTimeMillis();

    return new RequestContext(
        method,
        path,
        tenant,
        traceId,
        spanId,
        requestId,
        correlationId,
        headerCount,
        paramCount,
        ts);
  }

  private static String header(HttpServletRequest req, String name) {
    String v = req.getHeader(name);
    return (v == null || v.isBlank()) ? null : v;
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a;
    }
    if (b != null && !b.isBlank()) {
      return b;
    }
    return null;
  }

  private static String safe(String s) {
    return (s == null || s.isBlank()) ? "/" : s;
  }
}
