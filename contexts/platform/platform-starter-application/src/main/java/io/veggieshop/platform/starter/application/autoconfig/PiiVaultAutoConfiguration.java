package io.veggieshop.platform.starter.application.autoconfig;

import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Tracer;
import io.veggieshop.platform.application.consistency.ConsistencyProperties;
import io.veggieshop.platform.application.consistency.ConsistencyService;
import io.veggieshop.platform.application.consistency.ReadYourWritesGuard;
import io.veggieshop.platform.application.pii.PiiVaultClient;
import io.veggieshop.platform.application.security.AbacDefaults;
import io.veggieshop.platform.application.security.AbacPolicyEngine;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

@AutoConfiguration
@AutoConfigureAfter(name = "io.veggieshop.platform.starter.data.autoconfig.VeggiePiiVaultAutoConfiguration")
public class PiiVaultAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock appClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    AbacPolicyEngine abacPolicyEngine(MeterRegistry metrics,
                                      Clock clock,
                                      ObjectProvider<AbacDefaults> defaultsProvider) {
        AbacDefaults defaults = defaultsProvider.getIfAvailable(AbacDefaults::strict);
        return new AbacPolicyEngine(metrics, clock, defaults);
    }

    @Bean
    @ConditionalOnMissingBean
    AbacDefaults abacDefaults() {
        return AbacDefaults.strict();
    }

    @Bean
    @ConditionalOnMissingBean
    ReadYourWritesGuard readYourWritesGuard(ConsistencyService consistency,
                                            ConsistencyProperties props,
                                            Clock clock) {
        return new ReadYourWritesGuard(consistency, props, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    Tracer piiTracer() {
        return GlobalOpenTelemetry.get().getTracer("io.veggieshop.platform.pii");
    }

    @Bean
    @ConditionalOnBean(PiiVaultClient.PiiVaultPort.class)
    @ConditionalOnMissingBean
    PiiVaultClient piiVaultClient(PiiVaultClient.PiiVaultPort port,
                                  AbacPolicyEngine abac,
                                  ReadYourWritesGuard ryw,
                                  Tracer tracer,
                                  Clock clock) {
        return new PiiVaultClient(port, abac, ryw, tracer, clock);
    }
}
