package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.platform.http.error.ProblemHttpMapper;
import io.veggieshop.problem.core.ProblemFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * Auto-config for Problem+JSON (RFC7807) wiring. - Provides ProblemFactory & ProblemHttpMapper if
 * missing. - Registers ProblemExceptionAdvice without relying on component-scan.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DispatcherServlet.class)
@ConditionalOnProperty(
    prefix = "veggieshop.web.problem",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
@Import(ProblemExceptionAdvice.class)
public class ProblemWebAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public ProblemFactory problemFactory() {
    return new ProblemFactory();
  }

  @Bean
  @ConditionalOnMissingBean
  public ProblemHttpMapper problemHttpMapper() {
    return new ProblemHttpMapper();
  }

  @Bean
  @ConditionalOnMissingBean(RequestContextProvider.class)
  public RequestContextProvider requestContextProvider() {
    return new DefaultRequestContextProvider();
  }
}
