package io.veggieshop.platform.starter.consistency.web.autoconfig;

import io.veggieshop.platform.application.consistency.ConsistencyService;
import io.veggieshop.platform.application.consistency.ReadYourWritesGuard;
import io.veggieshop.platform.http.consistency.ConsistencyHeadersInterceptor;
import io.veggieshop.platform.http.consistency.ConsistencyPreconditionInterceptor;
import io.veggieshop.platform.http.consistency.EtagResponseAdvice;
import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Auto-configures web-layer consistency helpers.
 *
 * <ul>
 *   <li>Precondition interceptor (If-Consistent-With / If-Match)
 *   <li>Headers interceptor (Vary / X-Consistency-Token)
 *   <li>ETag response advice
 * </ul>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({WebMvcConfigurer.class, HandlerInterceptor.class})
@ConditionalOnBean(ConsistencyService.class)
@EnableConfigurationProperties(ConsistencyWebProperties.class)
public class ConsistencyWebAutoConfiguration {

  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency.precondition",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnMissingBean
  public ConsistencyPreconditionInterceptor consistencyPreconditionInterceptor(
      ConsistencyService consistencyService, ReadYourWritesGuard readYourWritesGuard) {
    return new ConsistencyPreconditionInterceptor(consistencyService, readYourWritesGuard);
  }

  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency.headers",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnMissingBean
  public ConsistencyHeadersInterceptor consistencyHeadersInterceptor(
      ConsistencyService consistencyService) {
    return new ConsistencyHeadersInterceptor(consistencyService);
  }

  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency.etag",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnMissingBean
  public EtagResponseAdvice etagResponseAdvice() {
    // Prefer annotating EtagResponseAdvice with @ControllerAdvice in the component itself.
    return new EtagResponseAdvice();
  }

  /**
   * Registers web interceptors for preconditions and consistency headers, applying include/exclude
   * path patterns from properties.
   *
   * @param props overall consistency web properties
   * @param preInterceptor interceptor that enforces request preconditions
   * @param postInterceptor interceptor that adds consistency headers
   * @return a {@link WebMvcConfigurer} that wires the interceptors
   */
  @ConditionalOnProperty(
      prefix = "veggieshop.web.consistency",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  @ConditionalOnClass(WebMvcConfigurer.class)
  @ConditionalOnBean({
    ConsistencyPreconditionInterceptor.class,
    ConsistencyHeadersInterceptor.class
  })
  public WebMvcConfigurer consistencyInterceptorsConfigurer(
      ConsistencyWebProperties props,
      ConsistencyPreconditionInterceptor preInterceptor,
      ConsistencyHeadersInterceptor postInterceptor) {
    return new WebMvcConfigurer() {
      @Override
      public void addInterceptors(@NonNull InterceptorRegistry registry) {
        if (props.getPrecondition().isEnabled()) {
          InterceptorRegistration reg =
              registry
                  .addInterceptor(preInterceptor)
                  .order(ConsistencyPreconditionInterceptor.ORDER);
          applyPatterns(
              reg,
              props.getPrecondition().getIncludePathPatterns(),
              props.getPrecondition().getExcludePathPatterns());
        }
        if (props.getHeaders().isEnabled()) {
          InterceptorRegistration reg =
              registry.addInterceptor(postInterceptor).order(ConsistencyHeadersInterceptor.ORDER);
          applyPatterns(
              reg,
              props.getHeaders().getIncludePathPatterns(),
              props.getHeaders().getExcludePathPatterns());
        }
      }
    };
  }

  // Helpers
  private static void applyPatterns(
      InterceptorRegistration reg, List<String> includes, List<String> excludes) {
    if (includes != null && !includes.isEmpty()) {
      reg.addPathPatterns(includes.toArray(String[]::new));
    } else {
      reg.addPathPatterns("/**");
    }
    if (excludes != null && !excludes.isEmpty()) {
      reg.excludePathPatterns(excludes.toArray(String[]::new));
    }
  }
}
