package io.veggieshop.platform.starter.security;

import io.veggieshop.platform.application.security.StepUpService;
import io.veggieshop.platform.http.security.StepUpSettings;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Clock;
import java.util.LinkedHashSet;

@AutoConfiguration
@EnableConfigurationProperties(StepUpWebProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(StepUpService.class)
@ConditionalOnProperty(prefix = "veggieshop.web.step-up", name = "enabled", havingValue = "true")
public class StepUpWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public StepUpSettings stepUpSettings(StepUpWebProperties p) {
        return new StepUpSettings.Builder()
                .defaultMaxAge(p.getDefaultMaxAge())
                .mfaAmrHints(new LinkedHashSet<>(p.getMfaAmrHints()))
                .allowHmacPrincipals(p.isAllowHmacPrincipals())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public StepUpInterceptor stepUpInterceptor(
            StepUpService service,
            StepUpSettings settings,
            ObjectProvider<Clock> clock
    ) {
        return new StepUpInterceptor(service, settings, clock.getIfAvailable(Clock::systemUTC));
    }

    @Bean
    public WebMvcConfigurer stepUpConfigurer(StepUpWebProperties props, StepUpInterceptor interceptor) {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                int order = (props.getOrder() != null) ? props.getOrder() : StepUpInterceptor.ORDER;
                registry.addInterceptor(interceptor).order(order);
            }
        };
    }
}
