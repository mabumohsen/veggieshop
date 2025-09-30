package io.veggieshop.platform.starter.security.web.autoconfig;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.veggieshop.platform.http.filters.OidcJwtAuthFilter;
import io.veggieshop.platform.http.filters.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.EnumSet;
import java.util.List;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

/** Wires Nimbus JWT processor + OIDC filter. Domain/Application remain framework-agnostic. */
@AutoConfiguration
@EnableConfigurationProperties(OidcWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({
  DispatcherServlet.class,
  OidcJwtAuthFilter.class,
  DefaultJWTProcessor.class,
  JWKSourceBuilder.class
})
@ConditionalOnProperty(prefix = "veggieshop.web.oidc", name = "enabled", havingValue = "true")
public class OidcWebAutoConfiguration {

  private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS =
      EnumSet.of(REQUEST, ERROR, ASYNC);

  // --------------------------- Nimbus JWT Processor ---------------------------

  /**
   * Builds a Nimbus {@link ConfigurableJWTProcessor} backed by a JWKS source. Audience/issuer
   * checks are enforced inside {@link OidcJwtAuthFilter}.
   *
   * @param p OIDC web properties
   * @return configured JWT processor
   * @throws IllegalStateException when JWKS URI is invalid or cannot be derived
   */
  @Bean
  @ConditionalOnMissingBean
  public ConfigurableJWTProcessor<SecurityContext> oidcJwtProcessor(OidcWebProperties p) {
    // Validate essential config (either issuer or jwksUri must be present)
    if (isBlank(p.getIssuer()) && isBlank(p.getJwksUri())) {
      throw new IllegalStateException(
          "veggieshop.web.oidc: either 'issuer' or 'jwks-uri' must be configured");
    }

    String jwksUri =
        !isBlank(p.getJwksUri()) ? p.getJwksUri() : deriveJwksFromIssuer(p.getIssuer());

    DefaultResourceRetriever retriever =
        new DefaultResourceRetriever(
            (int) p.getJwksConnectTimeout().toMillis(),
            (int) p.getJwksReadTimeout().toMillis(),
            p.getJwksSizeLimitBytes());

    URL jwksUrl;
    try {
      jwksUrl = URI.create(jwksUri).toURL();
    } catch (IllegalArgumentException | MalformedURLException e) {
      throw new IllegalStateException("Invalid JWKS URI: " + jwksUri, e);
    }

    JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.create(jwksUrl, retriever).build();

    List<String> algs = p.getAllowedAlgs().isEmpty() ? List.of("RS256") : p.getAllowedAlgs();
    JWSAlgorithm alg = JWSAlgorithm.parse(algs.get(0));

    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(alg, jwkSource);

    DefaultJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
    proc.setJWSKeySelector(keySelector);
    // Audience/issuer checks handled inside OidcJwtAuthFilter
    return proc;
  }

  private static String deriveJwksFromIssuer(String issuer) {
    String base = issuer.endsWith("/") ? issuer : issuer + "/";
    return URI.create(base).resolve(".well-known/jwks.json").toString();
  }

  private static boolean isBlank(String s) {
    return s == null || s.trim().isEmpty();
  }

  // --------------------------- Filter registration ---------------------------

  /**
   * Registers the {@link OidcJwtAuthFilter}.
   *
   * @param p OIDC web properties
   * @param processor Nimbus JWT processor used by the filter to validate tokens
   * @return the filter registration bean
   */
  @Bean(name = "oidcJwtAuthFilterRegistration")
  @ConditionalOnMissingBean(name = "oidcJwtAuthFilterRegistration")
  public FilterRegistrationBean<OidcJwtAuthFilter> oidcJwtAuthFilter(
      OidcWebProperties p, ConfigurableJWTProcessor<SecurityContext> processor) {
    // Use first audience from the configured set, when present.
    String audience = null;
    if (p.getAudience() != null && !p.getAudience().isEmpty()) {
      audience = p.getAudience().iterator().next();
    }

    OidcJwtAuthFilter filter =
        OidcJwtAuthFilter.of(
            p.getIssuer(),
            p.getAllowedAlgs(),
            p.getClockSkew(),
            audience,
            p.getPublicPaths(),
            processor);

    FilterRegistrationBean<OidcJwtAuthFilter> reg = new FilterRegistrationBean<>(filter);
    reg.setDispatcherTypes(DEFAULT_DISPATCHERS);
    reg.setOrder(p.getOrder() != null ? p.getOrder() : (RateLimitFilter.ORDER + 10));
    reg.addUrlPatterns("/*");
    reg.setAsyncSupported(true);
    return reg;
  }
}
