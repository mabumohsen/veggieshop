package io.veggieshop.platform.starter.tenancy.web.autoconfig;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

import io.veggieshop.platform.domain.tenant.TenantResolver;
import io.veggieshop.platform.http.filters.TenantFilter;
import jakarta.servlet.DispatcherType;
import java.util.EnumSet;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * Boot 3 auto-configuration for tenancy. Registers {@link TenantFilter} wired to the domain-level
 * {@link TenantResolver}.
 */
@AutoConfiguration
@EnableConfigurationProperties(WebTenancyProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({DispatcherServlet.class, TenantFilter.class})
@ConditionalOnProperty(
    prefix = "veggieshop.web.tenancy",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class TenancyWebAutoConfiguration {

  private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS =
      EnumSet.of(REQUEST, ERROR, ASYNC);

  /**
   * Registers {@link TenantFilter} for servlet requests.
   *
   * @param tenantResolver domain-level tenant resolver
   * @param p tenancy web properties
   * @return filter registration bean for {@code TenantFilter}
   */
  @Bean(name = "tenantFilterRegistration")
  @ConditionalOnMissingBean(name = "tenantFilterRegistration")
  public FilterRegistrationBean<TenantFilter> tenantFilter(
      TenantResolver tenantResolver, WebTenancyProperties p) {

    TenantFilter filter =
        new TenantFilter(
            tenantResolver, p.getHeader(), p.isRequired(), p.getPublicPaths(), p.getMdcKey());

    FilterRegistrationBean<TenantFilter> reg = new FilterRegistrationBean<>(filter);
    reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
    reg.setOrder(TenantFilter.ORDER);
    reg.addUrlPatterns("/*");
    reg.setAsyncSupported(true);
    return reg;
  }
}
