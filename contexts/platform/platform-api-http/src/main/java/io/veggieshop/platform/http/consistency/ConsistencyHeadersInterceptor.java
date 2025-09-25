package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.application.consistency.ConsistencyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.Objects;

/**
 * ConsistencyHeadersInterceptor
 *
 * - يضيف Vary: If-Consistent-With لكل الردود القابلة للتخزين الوسيط.
 * - يولّد X-Consistency-Token ويرسله للعميل (للقراءة والكتابة) عند النجاح.
 * - إن احتوى الطلب على نسخة الكيان (من ETagResponseAdvice) يضمّنها داخل التوكن لتحسين الاستدلالات.
 */
@Order(ConsistencyHeadersInterceptor.ORDER)
public final class ConsistencyHeadersInterceptor implements HandlerInterceptor {

    public static final int ORDER = Ordered.LOWEST_PRECEDENCE - 150;

    public static final String HDR_VARY               = "Vary";
    public static final String HDR_IF_CONSISTENT_WITH = ConsistencyPreconditionInterceptor.HDR_IF_CONSISTENT_WITH;
    public static final String HDR_CONSISTENCY_TOKEN  = ConsistencyPreconditionInterceptor.HDR_CONSISTENCY_TOKEN;

    /** اسم الخاصية التي يضبطها ETagResponseAdvice عند توفر نسخة الكيان. */
    public static final String ATTR_ENTITY_VERSION = ETagResponseAdvice.ATTR_ENTITY_VERSION;

    private final ConsistencyService consistency;

    public ConsistencyHeadersInterceptor(ConsistencyService consistency) {
        this.consistency = Objects.requireNonNull(consistency, "consistency");
    }

    @Override
    public void postHandle(@NonNull HttpServletRequest request,
                           @NonNull HttpServletResponse response,
                           @NonNull Object handler,
                           ModelAndView modelAndView) {
        // أضف Vary: If-Consistent-With (مرة واحدة)
        addVary(response, HDR_IF_CONSISTENT_WITH);

        // لا نرسل التوكن على الأخطاء
        int status = response.getStatus();
        if (status >= 400) {
            return;
        }

        // إن كان الهيدر موجوداً مسبقاً (وضعه الكونترولر) لا نستبدله
        if (response.getHeader(HDR_CONSISTENCY_TOKEN) != null) {
            return;
        }

        // يتطلب نطاق طلب مفتوحاً (ثُبّت في preHandle)
        if (consistency.currentTenant().isEmpty()) {
            return;
        }

        Long version = null;
        Object attr = request.getAttribute(ATTR_ENTITY_VERSION);
        if (attr instanceof Long v) version = v;

        String token = consistency.emitTokenForCurrentTenant(version);
        response.addHeader(HDR_CONSISTENCY_TOKEN, token);
    }

    private static void addVary(HttpServletResponse response, String headerName) {
        String existing = response.getHeader(HDR_VARY);
        if (existing == null) {
            response.setHeader(HDR_VARY, headerName);
        } else if (!containsToken(existing, headerName)) {
            response.setHeader(HDR_VARY, existing + ", " + headerName);
        }
    }

    private static boolean containsToken(String varyValue, String token) {
        for (String part : varyValue.split(",")) {
            if (part.trim().equalsIgnoreCase(token)) return true;
        }
        return false;
    }
}
