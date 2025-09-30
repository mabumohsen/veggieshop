package io.veggieshop.platform.starter.core.web.autoconfig;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

import io.veggieshop.platform.http.filters.CorrelationIdFilter;
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
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Core, always-on web wiring (no domain/app coupling).
 *
 * <ul>
 *   <li>ForwardedHeaderFilter (behind proxies/LB)
 *   <li>CorrelationIdFilter (request id / MDC)
 *   <li>Optional simple CORS from properties
 * </ul>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DispatcherServlet.class)
@EnableConfigurationProperties({
  CoreWebProperties.class,
  CorrelationProperties.class,
  CorsProperties.class
})
public class CoreWebAutoConfiguration {

  private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS =
      EnumSet.of(REQUEST, ERROR, ASYNC);

  // -----------------------------------------------------------------------------------------------
  // Forwarded headers
  // -----------------------------------------------------------------------------------------------

  /** Registers {@link ForwardedHeaderFilter} when enabled or not explicitly disabled. */
  @Bean
  @ConditionalOnMissingBean(ForwardedHeaderFilter.class)
  @ConditionalOnProperty(
      prefix = "veggieshop.web.core",
      name = "forwarded-enabled",
      havingValue = "true",
      matchIfMissing = true)
  public ForwardedHeaderFilter forwardedHeaderFilter() {
    return new ForwardedHeaderFilter();
  }

  // -----------------------------------------------------------------------------------------------
  // Correlation Id
  // -----------------------------------------------------------------------------------------------

  /**
   * Registers {@link CorrelationIdFilter} with configurable header/generator/MDC key.
   *
   * @param p correlation properties
   * @return filter registration bean
   */
  @Bean(name = "correlationIdFilterRegistration")
  @ConditionalOnProperty(
      prefix = "veggieshop.web.correlation",
      name = "enabled",
      matchIfMissing = true)
  @ConditionalOnMissingBean(name = "correlationIdFilterRegistration")
  public FilterRegistrationBean<CorrelationIdFilter> correlationIdFilter(CorrelationProperties p) {
    var filter =
        new CorrelationIdFilter(
            p.getHeader(), p.isGenerateIfMissing(), p.getGenerator().name(), p.getMdcKey());
    var reg = new FilterRegistrationBean<>(filter);
    reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
    reg.setOrder(CorrelationIdFilter.ORDER);
    reg.addUrlPatterns("/*");
    reg.setAsyncSupported(true);
    return reg;
  }

  // -----------------------------------------------------------------------------------------------
  // CORS (simple, optional)
  // -----------------------------------------------------------------------------------------------

  /**
   * Adds a simple global CORS mapping based on {@link CorsProperties}.
   *
   * @param p CORS properties
   */
  @Bean
  @ConditionalOnProperty(prefix = "veggieshop.web.cors", name = "enabled", havingValue = "true")
  public WebMvcConfigurer corsConfigurer(CorsProperties p) {
    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(CorsRegistry reg) {
        reg.addMapping("/**")
            .allowedOrigins(p.getAllowedOrigins().toArray(String[]::new))
            .allowedMethods(p.getAllowedMethods().toArray(String[]::new))
            .allowedHeaders(p.getAllowedHeaders().toArray(String[]::new))
            .exposedHeaders(p.getExposedHeaders().toArray(String[]::new))
            .allowCredentials(p.isAllowCredentials())
            .maxAge(p.getMaxAge().toSeconds());
      }
    };
  }
}
