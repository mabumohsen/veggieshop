package io.veggieshop.platform.http.filters;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.domain.tenant.TenantContext;
import io.veggieshop.platform.domain.tenant.TenantId;
import io.veggieshop.platform.domain.tenant.TenantResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.PathContainer;           // ✅ مهم
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.util.*;

@Order(TenantFilter.ORDER)
public final class TenantFilter extends OncePerRequestFilter {

    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 20;
    private static final Set<String> ALLOWLIST_EXACT = Set.of("/error", "/favicon.ico");

    private final TenantResolver tenantResolver;
    private final String headerName;
    private final boolean required;
    private final List<PathPattern> publicPatterns;
    private final String mdcKey;

    private static final PathPatternParser PPP = new PathPatternParser();

    public TenantFilter(
            TenantResolver tenantResolver,
            String headerName,
            boolean required,
            List<String> publicPaths,
            String mdcKey
    ) {
        this.tenantResolver = Objects.requireNonNull(tenantResolver, "tenantResolver");
        this.headerName = (headerName == null || headerName.isBlank())
                ? TenantContext.REQUEST_HEADER : headerName.trim();
        this.required = required;
        this.publicPatterns = compile(publicPaths);
        this.mdcKey = (mdcKey == null || mdcKey.isBlank())
                ? TenantContext.MDC_TENANT_ID : mdcKey.trim();
    }

    private static List<PathPattern> compile(List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) return List.of();
        List<PathPattern> list = new ArrayList<>(patterns.size());
        for (String p : patterns) {
            if (p != null && !p.isBlank()) list.add(PPP.parse(p.trim()));
        }
        return List.copyOf(list);
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        // CORS preflight
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                && request.getHeader("Access-Control-Request-Method") != null) {
            return true;
        }

        final String path = request.getServletPath();
        if (path == null || path.isEmpty()) return false;

        if (ALLOWLIST_EXACT.contains(path)) return true;

        PathContainer container = PathContainer.parsePath(path);
        for (PathPattern pattern : publicPatterns) {
            if (pattern.matches(container)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String rawHeader = firstHeaderValue(request.getHeader(this.headerName));

        if ((rawHeader == null || rawHeader.isBlank())) {
            if (required) {
                throw VeggieException.builder(ProblemTypes.TENANT_REQUIRED)
                        .detail("Missing required header: " + this.headerName)
                        .captureStackTrace(false)
                        .build();
            } else {
                filterChain.doFilter(request, response);
                return;
            }
        }

        final TenantId explicitTenantId;
        try {
            explicitTenantId = TenantId.of(rawHeader.trim());
        } catch (IllegalArgumentException ex) {
            throw VeggieException.builder(ProblemTypes.TENANT_UNKNOWN)
                    .detail("Invalid " + this.headerName + " value")
                    .cause(ex)
                    .captureStackTrace(false)
                    .build();
        }

        final Map<String, String> headersMap = headersMap(request);
        final TenantId tenantId;
        try {
            TenantResolver.Resolution res = tenantResolver.resolve(
                    explicitTenantId, headersMap, null, null
            );
            tenantId = res.tenantId();
        } catch (NoSuchElementException e) {
            throw VeggieException.builder(ProblemTypes.TENANT_REQUIRED)
                    .detail("Tenant could not be resolved from request")
                    .captureStackTrace(false)
                    .build();
        } catch (IllegalStateException e) {
            throw VeggieException.builder(ProblemTypes.TENANT_MISMATCH)
                    .detail("Conflicting tenant identifiers provided by multiple sources")
                    .cause(e)
                    .captureStackTrace(false)
                    .build();
        }

        try (var ignored = TenantContext.open(tenantId)) {
            if (!TenantContext.MDC_TENANT_ID.equals(this.mdcKey)) {
                MDC.put(this.mdcKey, tenantId.value());
            }
            request.setAttribute(attrTenantId(), tenantId);
            filterChain.doFilter(request, response);
        } finally {
            request.removeAttribute(attrTenantId());
            if (!TenantContext.MDC_TENANT_ID.equals(this.mdcKey)) {
                MDC.remove(this.mdcKey);
            }
        }
    }

    private static String firstHeaderValue(String raw) {
        if (raw == null) return null;
        int comma = raw.indexOf(',');
        return (comma >= 0 ? raw.substring(0, comma) : raw).trim();
    }

    private static Map<String, String> headersMap(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) return map;
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String value = firstHeaderValue(request.getHeader(name));
            if (value != null) map.put(name, value);
        }
        return map;
    }

    private static String attrTenantId() {
        return TenantFilter.class.getName() + ".TENANT_ID";
    }
}
