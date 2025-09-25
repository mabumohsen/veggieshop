package io.veggieshop.platform.starter.consistency.web.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

/**
 * خصائص ربط طبقة الويب للاتساق (Consistency).
 *
 * المفاتيح الرئيسية:
 *   veggieshop.web.consistency.enabled=true
 *
 * قابلة للتخصيص لكل مكوّن:
 *   veggieshop.web.consistency.precondition.enabled=true
 *   veggieshop.web.consistency.precondition.include-path-patterns[0]=/api/**    # أنماط Ant
 *   veggieshop.web.consistency.precondition.exclude-path-patterns[0]=/actuator/**
 *
 *   veggieshop.web.consistency.headers.enabled=true
 *   veggieshop.web.consistency.headers.include-path-patterns[0]=/api/**
 *   veggieshop.web.consistency.headers.exclude-path-patterns[0]=/actuator/**
 *
 *   veggieshop.web.consistency.etag.enabled=true
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.consistency")
public class ConsistencyWebProperties {

    /**
     * تمكين/تعطيل ربط الاتساق في طبقة الويب بالكامل.
     */
    private boolean enabled = true;

    /**
     * خصائص Interceptor الذي يعالج preconditions (If-Consistent-With / If-Match).
     */
    private final Section precondition = new Section(true);

    /**
     * خصائص Interceptor الذي يضيف Vary و X-Consistency-Token.
     */
    private final Section headers = new Section(true);

    /**
     * خصائص ResponseBodyAdvice الذي يضيف ETag تلقائياً.
     */
    private final EtagSection etag = new EtagSection(true);

    // ------------------------------------------------------------------------------------------------
    // Nested types
    // ------------------------------------------------------------------------------------------------

    public static class Section {
        private boolean enabled;
        private List<String> includePathPatterns = new ArrayList<>();
        private List<String> excludePathPatterns = defaultExcludes();

        public Section(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isEnabled() {
            return enabled;
        }
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getIncludePathPatterns() {
            return includePathPatterns;
        }
        public void setIncludePathPatterns(List<String> includePathPatterns) {
            this.includePathPatterns = (includePathPatterns == null) ? new ArrayList<>() : includePathPatterns;
        }

        public List<String> getExcludePathPatterns() {
            return excludePathPatterns;
        }
        public void setExcludePathPatterns(List<String> excludePathPatterns) {
            this.excludePathPatterns = (excludePathPatterns == null) ? new ArrayList<>() : excludePathPatterns;
        }
    }

    public static class EtagSection {
        private boolean enabled;

        public EtagSection(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isEnabled() {
            return enabled;
        }
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Defaults
    // ------------------------------------------------------------------------------------------------

    private static List<String> defaultExcludes() {
        List<String> list = new ArrayList<>();
        list.add("/error");
        list.add("/favicon.ico");
        // عادة لا نريد تفعيل المنطق على الـ actuator/static (يمكن تعديلها من الخصائص)
        list.add("/actuator/**");
        list.add("/assets/**");
        list.add("/static/**");
        return list;
    }

    // ------------------------------------------------------------------------------------------------
    // Getters / Setters
    // ------------------------------------------------------------------------------------------------

    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Section getPrecondition() {
        return precondition;
    }

    public Section getHeaders() {
        return headers;
    }

    public EtagSection getEtag() {
        return etag;
    }
}
