package io.veggieshop.platform.starter.ratelimit.web.autoconfig;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

import io.veggieshop.platform.http.filters.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import java.time.Duration;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
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
 * Registers {@link RateLimitFilter} for servlet applications using {@link RateLimitWebProperties}.
 */
@AutoConfiguration
@EnableConfigurationProperties(RateLimitWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({DispatcherServlet.class, RateLimitFilter.class})
public class RateLimitWebAutoConfiguration {

  private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS =
      EnumSet.of(REQUEST, ERROR, ASYNC);

  /**
   * Creates and registers the rate-limit filter.
   *
   * @param p the configuration properties
   * @return a configured {@link FilterRegistrationBean}
   */
  @Bean(name = "rateLimitFilterRegistration")
  @ConditionalOnMissingBean(name = "rateLimitFilterRegistration")
  @ConditionalOnProperty(
      prefix = "veggieshop.web.ratelimit",
      name = "enabled",
      matchIfMissing = true)
  public FilterRegistrationBean<RateLimitFilter> rateLimitFilter(RateLimitWebProperties p) {
    RateLimitFilter filter =
        new RateLimitFilter(
            p.isHeaders(),
            p.getKeys(),
            toPolicy(p.getDefaultPolicy()),
            toPolicyMap(p.getOverrides()),
            p.getMaxBuckets(),
            p.getIdleEvictAfter());

    FilterRegistrationBean<RateLimitFilter> reg = new FilterRegistrationBean<>(filter);
    reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
    reg.setOrder(RateLimitFilter.ORDER);
    reg.addUrlPatterns("/*");
    reg.setAsyncSupported(true);
    return reg;
  }

  // -------- helpers (convert props -> filter types) --------

  private static RateLimitFilter.Policy toPolicy(
      RateLimitWebProperties.RateLimitPolicyProps props) {
    if (props == null) {
      return new RateLimitFilter.Policy(100, 100, Duration.ofMinutes(1));
    }
    return new RateLimitFilter.Policy(
        props.getCapacity(), props.getRefillTokens(), props.getRefillPeriod());
  }

  private static LinkedHashMap<String, RateLimitFilter.Policy> toPolicyMap(
      Map<String, RateLimitWebProperties.RateLimitPolicyProps> in) {
    LinkedHashMap<String, RateLimitFilter.Policy> out = new LinkedHashMap<>();
    if (in != null) {
      in.forEach((k, v) -> out.put(k, toPolicy(v)));
    }
    return out;
  }
}
