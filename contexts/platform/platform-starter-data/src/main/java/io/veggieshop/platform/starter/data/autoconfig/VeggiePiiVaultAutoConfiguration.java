package io.veggieshop.platform.starter.data.autoconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.veggieshop.platform.application.pii.PiiVaultClient;
import io.veggieshop.platform.infrastructure.pii.PiiVaultJdbcAdapter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Auto-configuration wiring a {@link PiiVaultClient.PiiVaultPort} backed by JDBC.
 *
 * <p>Enabled by {@link VeggiePiiVaultProperties} and active when {@link JdbcTemplate} is present.
 */
@AutoConfiguration
@EnableConfigurationProperties(VeggiePiiVaultProperties.class)
@ConditionalOnClass(JdbcTemplate.class)
public class VeggiePiiVaultAutoConfiguration {

  /** Creates a JDBC-backed PII Vault port with optional Micrometer metrics. */
  @Bean(name = "piiVaultPort")
  @ConditionalOnMissingBean(PiiVaultClient.PiiVaultPort.class)
  public PiiVaultClient.PiiVaultPort piiVaultPort(
      JdbcTemplate jdbc,
      VeggiePiiVaultProperties props,
      ObjectMapper objectMapper,
      ObjectProvider<MeterRegistry> meters) {

    return new PiiVaultJdbcAdapter(jdbc, props, meters.getIfAvailable(), objectMapper);
  }
}
