package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.domain.version.ConsistencyStamped;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.util.ClassUtils;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.Objects;

/**
 * ETagResponseAdvice
 *
 * يضيف ETag تلقائياً عندما يكون الجسم ConsistencyStamped ولم يتم تعيين ETag مسبقاً.
 * كما يضع النسخة (long) في attribute لاستخدام ConsistencyHeadersInterceptor لضمّها في X-Consistency-Token.
 *
 * لا يحمل @ControllerAdvice عمداً؛ الـ starter يقوم بتعريفه كـ bean.
 */
public final class ETagResponseAdvice implements ResponseBodyAdvice<Object> {

    /** اسم الخاصية التي تحتوي نسخة الكيان (إن وُجدت). */
    public static final String ATTR_ENTITY_VERSION =
            ETagResponseAdvice.class.getName() + ".ENTITY_VERSION";

    // أنواع نتحاشى توليد ETag لها (streaming/ملفات)
    private static final boolean JACKSON2_PRESENT =
            ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", ETagResponseAdvice.class.getClassLoader());

    @Override
    public boolean supports(@NonNull MethodParameter returnType, @NonNull Class converterType) {
        // اترك Spring يمرّ عبر كل الردود؛ سنفحص في beforeBodyWrite الجسم والنوع
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  @NonNull MethodParameter returnType,
                                  @NonNull org.springframework.http.MediaType selectedContentType,
                                  @NonNull Class selectedConverterType,
                                  @NonNull ServerHttpRequest request,
                                  @NonNull ServerHttpResponse response) {
        HttpHeaders headers = response.getHeaders();

        // لا نكتب فوق ETag موجود
        if (headers.getETag() != null) {
            propagateVersionAttributeIfPossible(request, null);
            return body;
        }

        // استخرج النسخة من الجسم إن كان ConsistencyStamped
        Long version = null;
        if (body instanceof ConsistencyStamped stamped) {
            var optVersion = stamped.version();
            if (optVersion.isPresent()) {
                long v = optVersion.get().value(); // استخراج القيمة من EntityVersion
                if (v > 0) version = v;
            }
        }

        if (version != null) {
            headers.setETag(strongEtag(version));
            propagateVersionAttributeIfPossible(request, version);
        } else {
            // لا نسخة — لا تفعل شيئاً
            propagateVersionAttributeIfPossible(request, null);
        }

        return body;
    }

    private static String strongEtag(long version) {
        // strong ETag على شكل HEX ضمن علامات اقتباس
        return "\"" + Long.toHexString(version) + "\"";
    }

    /**
     * خزِّن النسخة في خاصية الطلب ليستعملها ConsistencyHeadersInterceptor داخل X-Consistency-Token.
     */
    private static void propagateVersionAttributeIfPossible(ServerHttpRequest request, Long versionOrNull) {
        if (request instanceof ServletServerHttpRequest servletReq) {
            HttpServletRequest http = servletReq.getServletRequest();
            if (versionOrNull != null) {
                http.setAttribute(ATTR_ENTITY_VERSION, versionOrNull);
            } else {
                // ضمنياً نزيلها كي لا نسرّب نسخة خاطئة بين مسارات
                http.removeAttribute(ATTR_ENTITY_VERSION);
            }
        }
    }
}
