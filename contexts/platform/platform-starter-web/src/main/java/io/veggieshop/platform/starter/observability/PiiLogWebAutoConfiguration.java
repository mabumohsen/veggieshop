package io.veggieshop.platform.starter.observability;

import io.veggieshop.platform.http.filters.PiiLogGuardFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

import java.util.EnumSet;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

/**
 * Registers PiiLogGuardFilter with sane defaults to prevent PII leaking in logs.
 * All wiring is confined to the starter; core remains framework-agnostic.
 */
@AutoConfiguration
@EnableConfigurationProperties(PiiLogWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({DispatcherServlet.class, PiiLogGuardFilter.class})
public class PiiLogWebAutoConfiguration {

    private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS = EnumSet.of(REQUEST, ERROR, ASYNC);

    @Bean(name = "piiLogGuardFilterRegistration")
    @ConditionalOnMissingBean(name = "piiLogGuardFilterRegistration")
    @ConditionalOnProperty(prefix = "veggieshop.web.observability.pii-log", name = "enabled", matchIfMissing = true)
    public FilterRegistrationBean<PiiLogGuardFilter> piiLogGuardFilter(PiiLogWebProperties p) {
        var filter = new PiiLogGuardFilter(
                p.getPayloadMaxChars(),
                p.getHeaderDenylist(),
                p.getRedactPatterns()
        );

        var reg = new FilterRegistrationBean<>(filter);
        reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
        reg.setOrder(PiiLogGuardFilter.ORDER);
        reg.addUrlPatterns("/*");
        reg.setAsyncSupported(true);
        return reg;
    }
}
