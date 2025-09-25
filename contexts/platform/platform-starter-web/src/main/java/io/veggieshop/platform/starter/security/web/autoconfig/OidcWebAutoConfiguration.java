package io.veggieshop.platform.starter.security.web.autoconfig;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.veggieshop.platform.http.filters.OidcJwtAuthFilter;
import io.veggieshop.platform.http.filters.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.DispatcherServlet;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.EnumSet;
import java.util.List;

import static jakarta.servlet.DispatcherType.ASYNC;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.REQUEST;

/**
 * Wires Nimbus JWT processor + OIDC filter.
 * Domain/Application remain framework-agnostic.
 */
@AutoConfiguration
@EnableConfigurationProperties(OidcWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ DispatcherServlet.class, OidcJwtAuthFilter.class, DefaultJWTProcessor.class, RemoteJWKSet.class })
@ConditionalOnProperty(prefix = "veggieshop.web.oidc", name = "enabled", havingValue = "true")
public class OidcWebAutoConfiguration {

    private static final EnumSet<DispatcherType> DEFAULT_DISPATCHERS = EnumSet.of(REQUEST, ERROR, ASYNC);

    // --------------------------- Nimbus JWT Processor ---------------------------

    @Bean
    @ConditionalOnMissingBean
    public ConfigurableJWTProcessor<SecurityContext> oidcJwtProcessor(OidcWebProperties p) {
        // Validate essential config (either issuer or jwksUri must be present)
        if (isBlank(p.getIssuer()) && isBlank(p.getJwksUri())) {
            throw new IllegalStateException("veggieshop.web.oidc: either 'issuer' or 'jwks-uri' must be configured");
        }

        String jwksUri = !isBlank(p.getJwksUri()) ? p.getJwksUri() : deriveJwksFromIssuer(p.getIssuer());

        DefaultResourceRetriever retriever = new DefaultResourceRetriever(
                (int) p.getJwksConnectTimeout().toMillis(),
                (int) p.getJwksReadTimeout().toMillis(),
                p.getJwksSizeLimitBytes()
        );

        URL jwksUrl;
        try {
            jwksUrl = new URL(jwksUri);
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid JWKS URI: " + jwksUri, e);
        }

        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(jwksUrl, retriever);

        List<String> algs = p.getAllowedAlgs().isEmpty() ? List.of("RS256") : p.getAllowedAlgs();
        JWSAlgorithm alg = JWSAlgorithm.parse(algs.get(0));

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(alg, jwkSource);

        DefaultJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
        proc.setJWSKeySelector(keySelector);
        // You can add audience/issuer claim checks inside the filter (preferred) or via proc.setJWTClaimsSetVerifier(...)
        return proc;
    }

    private static String deriveJwksFromIssuer(String issuer) {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return base + "/.well-known/jwks.json";
    }

    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

    // --------------------------- Filter registration ---------------------------

    @Bean(name = "oidcJwtAuthFilterRegistration")
    @ConditionalOnMissingBean(name = "oidcJwtAuthFilterRegistration")
    public FilterRegistrationBean<OidcJwtAuthFilter> oidcJwtAuthFilter(
            OidcWebProperties p,
            ConfigurableJWTProcessor<SecurityContext> processor
    ) {
        // خذ أول audience من الـ Set (إن وُجد)
        String audience = null;
        if (p.getAudience() != null && !p.getAudience().isEmpty()) {
            audience = p.getAudience().iterator().next();
        }

        OidcJwtAuthFilter filter = OidcJwtAuthFilter.of(
                p.getIssuer(),
                p.getJwksUri(),
                p.getAllowedAlgs(),
                p.getClockSkew(),
                audience,
                p.getPublicPaths(),
                processor
        );

        FilterRegistrationBean<OidcJwtAuthFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setDispatcherTypes(EnumSet.of(REQUEST, ERROR, ASYNC));
        reg.setOrder(p.getOrder() != null ? p.getOrder() : (RateLimitFilter.ORDER + 10));
        reg.addUrlPatterns("/*");
        reg.setAsyncSupported(true);
        return reg;
    }

}
