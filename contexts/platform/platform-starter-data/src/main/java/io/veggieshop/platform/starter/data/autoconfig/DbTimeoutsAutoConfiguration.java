package io.veggieshop.platform.starter.data.autoconfig;

import com.zaxxer.hikari.HikariDataSource;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.function.LongConsumer;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.autoconfigure.transaction.TransactionManagerCustomizer;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Auto-configuration that applies sensible timeouts and tuning for HikariCP, PostgreSQL driver, and
 * Spring transaction managers (JDBC &amp; JPA).
 *
 * <p>Enabled via {@code veggieshop.db.enabled=true} (defaults to true). See {@link
 * DbTuningProperties} for all configurable properties.
 */
@AutoConfiguration
@AutoConfigureAfter({
  DataSourceAutoConfiguration.class,
  DataSourceTransactionManagerAutoConfiguration.class
})
@EnableConfigurationProperties(DbTimeoutsAutoConfiguration.DbTuningProperties.class)
@ConditionalOnClass({DataSource.class, HikariDataSource.class})
@ConditionalOnProperty(
    prefix = "veggieshop.db",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class DbTimeoutsAutoConfiguration {

  private static final Logger log = LoggerFactory.getLogger(DbTimeoutsAutoConfiguration.class);

  // -------------------------------------------------------------------------------------
  // Hikari customizer (applies to every HikariDataSource bean)
  // -------------------------------------------------------------------------------------

  /**
   * Customizes every {@link HikariDataSource} by applying pool sizing, Hikari timeouts, and
   * optional PostgreSQL driver/server tuning based on {@link DbTuningProperties}.
   */
  @Bean
  @ConditionalOnMissingBean(name = "hikariTimeoutsCustomizer")
  public BeanPostProcessor hikariTimeoutsCustomizer(DbTuningProperties props) {
    return new BeanPostProcessor() {
      @Override
      public Object postProcessBeforeInitialization(Object bean, String beanName) {
        if (!(bean instanceof HikariDataSource ds) || !props.isEnabled()) {
          return bean;
        }

        // ----- Pool sizing -----
        int maxPool =
            props.getMaxPoolSize() > 0
                ? props.getMaxPoolSize()
                : computeDefaultMaxPoolSize(props.getPoolSizeMin(), props.getPoolSizeMax());
        safeSetMaxPoolSize(ds, maxPool);

        // ----- Hikari timeouts -----
        setIfPositive("connectionTimeout", props.getConnectionTimeout(), ds::setConnectionTimeout);
        setIfPositive("validationTimeout", props.getValidationTimeout(), ds::setValidationTimeout);
        setIfPositive("idleTimeout", props.getIdleTimeout(), ds::setIdleTimeout);
        setIfPositive("maxLifetime", props.getMaxLifetime(), ds::setMaxLifetime);

        if (props.getLeakDetectionThreshold().toMillis() > 0) {
          ds.setLeakDetectionThreshold(props.getLeakDetectionThreshold().toMillis());
        }

        // ----- PostgreSQL driver/server tuning -----
        final String url = ds.getJdbcUrl() != null ? ds.getJdbcUrl().toLowerCase(Locale.ROOT) : "";
        final boolean isPg = url.startsWith("jdbc:postgresql:");

        if (isPg && props.isApplyPgTuning()) {
          // Driver-level socketTimeout (seconds) + tcpKeepAlive
          if (props.getPgSocketTimeoutSeconds() > 0) {
            ds.addDataSourceProperty(
                "socketTimeout", String.valueOf(props.getPgSocketTimeoutSeconds()));
          }
          ds.addDataSourceProperty("tcpKeepAlive", "true");

          // Server-side statement/idle timeouts via connectionInitSql
          String initSql = buildPgInitSql(props);
          if (!initSql.isBlank()) {
            if (ds.getConnectionInitSql() == null || ds.getConnectionInitSql().isBlank()) {
              ds.setConnectionInitSql(initSql);
            } else {
              ds.setConnectionInitSql(ds.getConnectionInitSql() + "; " + initSql);
            }
          }
        }

        String pgInfo =
            isPg && props.isApplyPgTuning()
                ? String.format(
                    ", pg[statement_timeout=%s, idle_in_tx_session_timeout=%s, socketTimeout=%ds]",
                    human(props.getPgStatementTimeout()),
                    human(props.getPgIdleInTxSessionTimeout()),
                    props.getPgSocketTimeoutSeconds())
                : "";

        log.info(
            ("HikariDataSource[{}]: maxPoolSize={}, connTimeout={}, validationTimeout={}, "
                + "idleTimeout={}, maxLifetime={}{}"),
            beanName,
            ds.getMaximumPoolSize(),
            human(props.getConnectionTimeout()),
            human(props.getValidationTimeout()),
            human(props.getIdleTimeout()),
            human(props.getMaxLifetime()),
            pgInfo);

        return bean;
      }

      private void safeSetMaxPoolSize(HikariDataSource ds, int size) {
        try {
          ds.setMaximumPoolSize(size);
        } catch (IllegalArgumentException ex) {
          int fallback = Math.max(size, ds.getMinimumIdle());
          ds.setMaximumPoolSize(fallback);
          log.warn(
              "Adjusted Hikari maximumPoolSize from {} to {} to satisfy minimumIdle={}",
              size,
              fallback,
              ds.getMinimumIdle());
        }
      }

      private void setIfPositive(String label, Duration v, LongConsumer setter) {
        long ms = v.toMillis();
        if (ms > 0) {
          setter.accept(ms);
        } else {
          log.debug("Skipped {} ({}ms not positive)", label, ms);
        }
      }

      private String buildPgInitSql(DbTuningProperties p) {
        StringBuilder sb = new StringBuilder(64);
        if (p.getPgStatementTimeout().toMillis() > 0) {
          sb.append("SET statement_timeout = ")
              .append(p.getPgStatementTimeout().toMillis())
              .append("; ");
        }
        if (p.getPgIdleInTxSessionTimeout().toMillis() > 0) {
          sb.append("SET idle_in_transaction_session_timeout = ")
              .append(p.getPgIdleInTxSessionTimeout().toMillis())
              .append("; ");
        }
        return sb.toString().trim();
      }

      private String human(Duration d) {
        if (d == null) {
          return "PT0S";
        }
        long ms = d.toMillis();
        if (ms == 0) {
          return "disabled";
        }
        return (ms % 1000 == 0) ? (ms / 1000) + "s" : ms + "ms";
      }

      private int computeDefaultMaxPoolSize(int min, int max) {
        int cpus = Math.max(1, Runtime.getRuntime().availableProcessors());
        // Heuristic: 4 connections per vCPU, bounded [min..max]
        int computed = cpus * 4;
        if (computed < min) {
          computed = min;
        }
        if (computed > max) {
          computed = max;
        }
        return computed;
      }
    };
  }

  // -------------------------------------------------------------------------------------
  // Transaction default timeout (applies to JDBC & JPA managers)
  // -------------------------------------------------------------------------------------

  @Bean
  @ConditionalOnMissingBean(name = "jdbcTxManagerCustomizer")
  public TransactionManagerCustomizer<DataSourceTransactionManager> jdbcTxManagerCustomizer(
      DbTuningProperties props) {
    return (DataSourceTransactionManager tm) -> applyTxDefaults("JDBC", tm, props);
  }

  @Bean
  @ConditionalOnMissingBean(name = "jpaTxManagerCustomizer")
  public TransactionManagerCustomizer<JpaTransactionManager> jpaTxManagerCustomizer(
      DbTuningProperties props) {
    return (JpaTransactionManager tm) -> applyTxDefaults("JPA", tm, props);
  }

  private void applyTxDefaults(
      String kind, PlatformTransactionManager tm, DbTuningProperties props) {
    Objects.requireNonNull(tm, "transactionManager");
    int timeoutSec = Math.toIntExact(props.getTxDefaultTimeout().toSeconds());
    if (tm instanceof DataSourceTransactionManager dsm) {
      dsm.setDefaultTimeout(timeoutSec);
      dsm.setRollbackOnCommitFailure(props.isRollbackOnCommitFailure());
      dsm.setEnforceReadOnly(props.isEnforceReadOnly());
    } else if (tm instanceof JpaTransactionManager jpa) {
      jpa.setDefaultTimeout(timeoutSec);
      jpa.setRollbackOnCommitFailure(props.isRollbackOnCommitFailure());
      jpa.setValidateExistingTransaction(true);
    }

    log.info(
        ("Applied {} transaction defaults: timeout={}s, rollbackOnCommitFailure={}, "
            + "enforceReadOnly={}"),
        kind,
        timeoutSec,
        props.isRollbackOnCommitFailure(),
        props.isEnforceReadOnly());
  }

  // -------------------------------------------------------------------------------------
  // Properties
  // -------------------------------------------------------------------------------------

  /**
   * Configuration properties for DB tuning applied by {@link DbTimeoutsAutoConfiguration}.
   *
   * <ul>
   *   <li>HikariCP sizing and timeouts
   *   <li>PostgreSQL driver/server timeouts
   *   <li>Default Spring transaction behavior
   * </ul>
   */
  @ConfigurationProperties(prefix = "veggieshop.db")
  public static class DbTuningProperties {
    /** Master switch for this tuning config. */
    private boolean enabled = true;

    /** Default Spring transaction timeout (applies to JDBC &amp; JPA managers). */
    private Duration txDefaultTimeout = Duration.ofSeconds(3);

    /** Rollback on commit failures; recommended true to avoid silent partial commits. */
    private boolean rollbackOnCommitFailure = true;

    /** Enforce readOnly semantics at JDBC level when @Transactional(readOnly=true). */
    private boolean enforceReadOnly = true;

    // ---- Hikari pool/timeouts ----
    /**
     * Compute maximumPoolSize if not explicitly set: 4 * vCPU bounded by
     * [poolSizeMin..poolSizeMax].
     */
    private int maxPoolSize = -1;

    private int poolSizeMin = 16;
    private int poolSizeMax = 64;

    private Duration connectionTimeout = Duration.ofSeconds(2);
    private Duration validationTimeout = Duration.ofSeconds(1);
    private Duration idleTimeout = Duration.ofSeconds(60);
    private Duration maxLifetime = Duration.ofMinutes(30);
    private Duration leakDetectionThreshold = Duration.ZERO;

    // ---- PostgreSQL specific ----
    private boolean applyPgTuning = true;
    private int pgSocketTimeoutSeconds = 5;
    private Duration pgStatementTimeout = Duration.ofMillis(2500);
    private Duration pgIdleInTxSessionTimeout = Duration.ofSeconds(5);

    // ---- getters/setters ----
    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public Duration getTxDefaultTimeout() {
      return txDefaultTimeout;
    }

    public void setTxDefaultTimeout(Duration txDefaultTimeout) {
      this.txDefaultTimeout = txDefaultTimeout;
    }

    public boolean isRollbackOnCommitFailure() {
      return rollbackOnCommitFailure;
    }

    public void setRollbackOnCommitFailure(boolean rollbackOnCommitFailure) {
      this.rollbackOnCommitFailure = rollbackOnCommitFailure;
    }

    public boolean isEnforceReadOnly() {
      return enforceReadOnly;
    }

    public void setEnforceReadOnly(boolean enforceReadOnly) {
      this.enforceReadOnly = enforceReadOnly;
    }

    public int getMaxPoolSize() {
      return maxPoolSize;
    }

    public void setMaxPoolSize(int maxPoolSize) {
      this.maxPoolSize = maxPoolSize;
    }

    public int getPoolSizeMin() {
      return poolSizeMin;
    }

    public void setPoolSizeMin(int poolSizeMin) {
      this.poolSizeMin = poolSizeMin;
    }

    public int getPoolSizeMax() {
      return poolSizeMax;
    }

    public void setPoolSizeMax(int poolSizeMax) {
      this.poolSizeMax = poolSizeMax;
    }

    public Duration getConnectionTimeout() {
      return connectionTimeout;
    }

    public void setConnectionTimeout(Duration connectionTimeout) {
      this.connectionTimeout = connectionTimeout;
    }

    public Duration getValidationTimeout() {
      return validationTimeout;
    }

    public void setValidationTimeout(Duration validationTimeout) {
      this.validationTimeout = validationTimeout;
    }

    public Duration getIdleTimeout() {
      return idleTimeout;
    }

    public void setIdleTimeout(Duration idleTimeout) {
      this.idleTimeout = idleTimeout;
    }

    public Duration getMaxLifetime() {
      return maxLifetime;
    }

    public void setMaxLifetime(Duration maxLifetime) {
      this.maxLifetime = maxLifetime;
    }

    public Duration getLeakDetectionThreshold() {
      return leakDetectionThreshold;
    }

    public void setLeakDetectionThreshold(Duration leakDetectionThreshold) {
      this.leakDetectionThreshold = leakDetectionThreshold;
    }

    public boolean isApplyPgTuning() {
      return applyPgTuning;
    }

    public void setApplyPgTuning(boolean applyPgTuning) {
      this.applyPgTuning = applyPgTuning;
    }

    public int getPgSocketTimeoutSeconds() {
      return pgSocketTimeoutSeconds;
    }

    public void setPgSocketTimeoutSeconds(int pgSocketTimeoutSeconds) {
      this.pgSocketTimeoutSeconds = pgSocketTimeoutSeconds;
    }

    public Duration getPgStatementTimeout() {
      return pgStatementTimeout;
    }

    public void setPgStatementTimeout(Duration pgStatementTimeout) {
      this.pgStatementTimeout = pgStatementTimeout;
    }

    public Duration getPgIdleInTxSessionTimeout() {
      return pgIdleInTxSessionTimeout;
    }

    public void setPgIdleInTxSessionTimeout(Duration pgIdleInTxSessionTimeout) {
      this.pgIdleInTxSessionTimeout = pgIdleInTxSessionTimeout;
    }
  }
}
