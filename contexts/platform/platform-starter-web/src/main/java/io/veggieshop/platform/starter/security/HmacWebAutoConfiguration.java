package io.veggieshop.platform.starter.security;

import io.veggieshop.platform.http.filters.HmacAuthFilter;
import io.veggieshop.platform.http.filters.TenantFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

import java.time.Clock;
import java.util.EnumSet;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

/**
 * Registers the HMAC partner-auth filter.
 * All wiring is confined to the starter; domain/application remain framework-agnostic.
 */
@AutoConfiguration
@EnableConfigurationProperties(HmacWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ DispatcherServlet.class, HmacAuthFilter.class })
@ConditionalOnProperty(prefix = "veggieshop.web.hmac", name = "enabled", havingValue = "true")
public class HmacWebAutoConfiguration {

    private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS = EnumSet.of(REQUEST, ERROR, ASYNC);

    @Bean(name = "hmacAuthFilterRegistration")
    @ConditionalOnMissingBean(name = "hmacAuthFilterRegistration")
    public FilterRegistrationBean<HmacAuthFilter> hmacAuthFilter(
            HmacWebProperties p,
            HmacAuthFilter.HmacKeyResolver keyResolver,
            ObjectProvider<HmacAuthFilter.NonceStore> nonceStore,
            ObjectProvider<Clock> clockProvider
    ) {
        // fall back to in-memory nonce store if none is provided by the app
        HmacAuthFilter.NonceStore ns = nonceStore.getIfAvailable(
                () -> HmacAuthFilter.inMemoryNonceStore(p.getNonceCacheSize(), p.getTtl())
        );

        String alg = p.getAcceptedAlgorithms().isEmpty()
                ? "HmacSHA256"
                : p.getAcceptedAlgorithms().get(0);

        HmacAuthFilter filter = new HmacAuthFilter(
                keyResolver,
                ns,
                clockProvider.getIfAvailable(Clock::systemUTC),
                p.getKeyIdHeader(),
                p.getTimestampHeader(),
                p.getNonceHeader(),
                p.getSignatureHeader(),
                p.getMaxBodyBytes(),
                p.getClockSkew(),
                p.isEnforceBodySha256(),
                alg
        );

        FilterRegistrationBean<HmacAuthFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
        // Run after tenant filter (needs tenant) and before OIDC; tweak via property if needed.
        int order = (p.getOrder() != null) ? p.getOrder() : (TenantFilter.ORDER + 15);
        reg.setOrder(order);
        reg.addUrlPatterns("/*");
        reg.setAsyncSupported(true);
        return reg;
    }
}
