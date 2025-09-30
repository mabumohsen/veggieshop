package io.veggieshop.platform.starter.messaging.autoconfig;

import com.google.protobuf.Message;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.confluent.kafka.serializers.AbstractKafkaSchemaSerDeConfig;
import io.confluent.kafka.serializers.KafkaAvroDeserializer;
import io.confluent.kafka.serializers.KafkaAvroDeserializerConfig;
import io.confluent.kafka.serializers.KafkaAvroSerializer;
import io.confluent.kafka.serializers.protobuf.KafkaProtobufDeserializer;
import io.confluent.kafka.serializers.protobuf.KafkaProtobufSerializer;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaAdmin;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.ExponentialBackOffWithMaxRetries;
import org.springframework.kafka.support.ProducerListener;
import org.springframework.kafka.transaction.KafkaTransactionManager;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.util.StringUtils;
import org.springframework.util.unit.DataSize;

@Configuration
@EnableKafka
@EnableConfigurationProperties(KafkaDefaultsConfiguration.VeggieKafkaProperties.class)
@SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
public class KafkaDefaultsConfiguration implements EnvironmentAware {

  private final KafkaProperties springKafka;
  private final VeggieKafkaProperties props;
  private final SslBundles sslBundles;
  private Environment environment;

  @SuppressFBWarnings({"EI_EXPOSE_REP2"})
  public KafkaDefaultsConfiguration(
      KafkaProperties springKafka, VeggieKafkaProperties props, SslBundles sslBundles) {
    this.springKafka = springKafka;
    this.props = props;
    this.sslBundles = sslBundles;
  }

  @Override
  public void setEnvironment(Environment environment) {
    this.environment = environment;
  }

  // ========= Admin =========
  @Bean
  @ConditionalOnMissingBean
  public KafkaAdmin kafkaAdmin() {
    Map<String, Object> cfg = new HashMap<>(springKafka.buildAdminProperties(sslBundles));
    cfg.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers());
    maybeSecurity(cfg);
    return new KafkaAdmin(cfg);
  }

  // ========= Producer (Avro – default) =========
  @Bean
  @ConditionalOnMissingBean(name = "avroProducerFactory")
  public ProducerFactory<String, Object> avroProducerFactory() {
    Map<String, Object> cfg = baseProducerProps();
    cfg.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
    cfg.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaAvroSerializer.class);
    schemaRegistry(cfg);
    DefaultKafkaProducerFactory<String, Object> pf = new DefaultKafkaProducerFactory<>(cfg);
    if (StringUtils.hasText(props.getProducer().getTransactionalIdPrefix())) {
      pf.setTransactionIdPrefix(props.getProducer().getTransactionalIdPrefix());
    }
    return pf;
  }

  @Bean
  @ConditionalOnMissingBean(name = "kafkaTemplate")
  public KafkaTemplate<String, Object> kafkaTemplate(
      @Qualifier("avroProducerFactory") ProducerFactory<String, Object> pf,
      ObjectProvider<ProducerListener<String, Object>> maybeListener) {
    KafkaTemplate<String, Object> tpl = new KafkaTemplate<>(pf);
    tpl.setObservationEnabled(true);
    ProducerListener<String, Object> listener = maybeListener.getIfAvailable();
    if (listener != null) {
      tpl.setProducerListener(listener);
    }
    return tpl;
  }

  @Bean
  @ConditionalOnMissingBean
  public KafkaTransactionManager<String, Object> kafkaTransactionManager(
      @Qualifier("avroProducerFactory") ProducerFactory<String, Object> pf) {
    KafkaTransactionManager<String, Object> tm = new KafkaTransactionManager<>(pf);
    tm.setTransactionSynchronization(
        AbstractPlatformTransactionManager.SYNCHRONIZATION_ON_ACTUAL_TRANSACTION);
    return tm;
  }

  // ========= Producer (Protobuf – optional) =========
  @Bean
  @ConditionalOnMissingBean(name = "protobufProducerFactory")
  public ProducerFactory<String, Message> protobufProducerFactory() {
    Map<String, Object> cfg = baseProducerProps();
    cfg.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
    cfg.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaProtobufSerializer.class);
    schemaRegistry(cfg);
    DefaultKafkaProducerFactory<String, Message> pf = new DefaultKafkaProducerFactory<>(cfg);
    if (StringUtils.hasText(props.getProducer().getTransactionalIdPrefix())) {
      pf.setTransactionIdPrefix(props.getProducer().getTransactionalIdPrefix());
    }
    return pf;
  }

  @Bean
  @ConditionalOnMissingBean(name = "protobufKafkaTemplate")
  public KafkaTemplate<String, Message> protobufKafkaTemplate(
      @Qualifier("protobufProducerFactory") ProducerFactory<String, Message> pf) {
    KafkaTemplate<String, Message> tpl = new KafkaTemplate<>(pf);
    tpl.setObservationEnabled(true);
    return tpl;
  }

  // ========= Consumer (Avro) =========
  @Bean
  @ConditionalOnMissingBean(name = "avroConsumerFactory")
  public ConsumerFactory<String, Object> avroConsumerFactory() {
    Map<String, Object> cfg = baseConsumerProps();
    cfg.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
    cfg.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, KafkaAvroDeserializer.class);
    cfg.put(KafkaAvroDeserializerConfig.SPECIFIC_AVRO_READER_CONFIG, true);
    schemaRegistry(cfg);
    return new DefaultKafkaConsumerFactory<>(cfg);
  }

  @Bean
  @ConditionalOnMissingBean(name = "kafkaListenerContainerFactory")
  public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory(
      @Qualifier("avroConsumerFactory") ConsumerFactory<String, Object> cf,
      @Qualifier("avroDltRecoverer") DeadLetterPublishingRecoverer dltRecoverer) {

    ConcurrentKafkaListenerContainerFactory<String, Object> f =
        new ConcurrentKafkaListenerContainerFactory<>();
    f.setConsumerFactory(cf);
    f.getContainerProperties().setObservationEnabled(true);
    f.getContainerProperties().setPollTimeout(props.getConsumer().getPollTimeout().toMillis());
    f.getContainerProperties().setAckMode(props.getConsumer().getAckMode());
    f.setConcurrency(props.getConsumer().getConcurrency());

    ExponentialBackOffWithMaxRetries backoff =
        new ExponentialBackOffWithMaxRetries(props.getConsumer().getMaxRetries());
    backoff.setInitialInterval(props.getConsumer().getRetryBackoff().toMillis());
    backoff.setMultiplier(props.getConsumer().getRetryMultiplier());
    backoff.setMaxInterval(props.getConsumer().getMaxRetryBackoff().toMillis());

    DefaultErrorHandler eh = new DefaultErrorHandler(dltRecoverer, backoff);
    props.getConsumer().getFatalExceptions().forEach(eh::addNotRetryableExceptions);
    f.setCommonErrorHandler(eh);

    return f;
  }

  // ========= Consumer (Protobuf) =========
  @Bean
  @ConditionalOnMissingBean(name = "protobufConsumerFactory")
  public ConsumerFactory<String, Message> protobufConsumerFactory() {
    Map<String, Object> cfg = baseConsumerProps();
    cfg.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
    cfg.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, KafkaProtobufDeserializer.class);
    schemaRegistry(cfg);
    return new DefaultKafkaConsumerFactory<>(cfg);
  }

  @Bean
  @ConditionalOnMissingBean(name = "protobufKafkaListenerContainerFactory")
  public ConcurrentKafkaListenerContainerFactory<String, Message>
      protobufKafkaListenerContainerFactory(
          @Qualifier("protobufConsumerFactory") ConsumerFactory<String, Message> cf,
          @Qualifier("protobufDltRecoverer") DeadLetterPublishingRecoverer dltRecoverer) {

    ConcurrentKafkaListenerContainerFactory<String, Message> f =
        new ConcurrentKafkaListenerContainerFactory<>();
    f.setConsumerFactory(cf);
    f.getContainerProperties().setObservationEnabled(true);
    f.getContainerProperties().setPollTimeout(props.getConsumer().getPollTimeout().toMillis());
    f.getContainerProperties().setAckMode(props.getConsumer().getAckMode());
    f.setConcurrency(props.getConsumer().getConcurrency());

    ExponentialBackOffWithMaxRetries backoff =
        new ExponentialBackOffWithMaxRetries(props.getConsumer().getMaxRetries());
    backoff.setInitialInterval(props.getConsumer().getRetryBackoff().toMillis());
    backoff.setMultiplier(props.getConsumer().getRetryMultiplier());
    backoff.setMaxInterval(props.getConsumer().getMaxRetryBackoff().toMillis());

    DefaultErrorHandler eh = new DefaultErrorHandler(dltRecoverer, backoff);
    props.getConsumer().getFatalExceptions().forEach(eh::addNotRetryableExceptions);
    f.setCommonErrorHandler(eh);

    return f;
  }

  // ========= DLQ (separate for Avro/Protobuf) =========
  @Bean
  @ConditionalOnMissingBean(name = "avroDltRecoverer")
  public DeadLetterPublishingRecoverer avroDltRecoverer(
      @Qualifier("kafkaTemplate") KafkaTemplate<String, Object> avroTemplate) {
    return new DeadLetterPublishingRecoverer(
        avroTemplate,
        (record, ex) ->
            new TopicPartition(record.topic() + props.getDltSuffix(), record.partition()));
  }

  @Bean
  @ConditionalOnMissingBean(name = "protobufDltRecoverer")
  public DeadLetterPublishingRecoverer protobufDltRecoverer(
      @Qualifier("protobufKafkaTemplate") KafkaTemplate<String, Message> protobufTemplate) {
    return new DeadLetterPublishingRecoverer(
        protobufTemplate,
        (record, ex) ->
            new TopicPartition(record.topic() + props.getDltSuffix(), record.partition()));
  }

  // ========= Shared props =========
  private Map<String, Object> baseProducerProps() {
    Map<String, Object> cfg = new HashMap<>(springKafka.buildProducerProperties(sslBundles));
    cfg.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers());
    cfg.put(ProducerConfig.ACKS_CONFIG, props.getProducer().getAcks());
    cfg.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
    cfg.put(
        ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,
        (int) props.getProducer().getDeliveryTimeout().toMillis());
    cfg.put(
        ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG,
        (int) props.getProducer().getRequestTimeout().toMillis());
    cfg.put(ProducerConfig.RETRIES_CONFIG, Integer.MAX_VALUE);
    cfg.put(ProducerConfig.LINGER_MS_CONFIG, (int) props.getProducer().getLinger().toMillis());
    cfg.put(ProducerConfig.BATCH_SIZE_CONFIG, (int) props.getProducer().getBatchSize().toBytes());
    cfg.put(ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION, 5);
    cfg.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, props.getProducer().getCompression());
    cfg.put(ProducerConfig.CLIENT_ID_CONFIG, buildClientId());
    cfg.put("allow.auto.create.topics", false);
    maybeSecurity(cfg);
    return cfg;
  }

  private Map<String, Object> baseConsumerProps() {
    Map<String, Object> cfg = new HashMap<>(springKafka.buildConsumerProperties(sslBundles));
    cfg.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers());
    cfg.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
    cfg.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, props.getConsumer().getAutoOffsetReset());
    cfg.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, props.getConsumer().getMaxPollRecords());
    cfg.put(
        ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG,
        (int) props.getConsumer().getMaxPollInterval().toMillis());
    cfg.put(
        ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG,
        (int) props.getConsumer().getSessionTimeout().toMillis());
    cfg.put(
        ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG,
        (int) props.getConsumer().getHeartbeatInterval().toMillis());
    cfg.put(
        ConsumerConfig.FETCH_MAX_WAIT_MS_CONFIG,
        (int) props.getConsumer().getFetchMaxWait().toMillis());
    cfg.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");
    cfg.put("allow.auto.create.topics", false);
    maybeSecurity(cfg);
    return cfg;
  }

  private void schemaRegistry(Map<String, Object> cfg) {
    if (StringUtils.hasText(props.getSchemaRegistry().getUrl())) {
      cfg.put(
          AbstractKafkaSchemaSerDeConfig.SCHEMA_REGISTRY_URL_CONFIG,
          props.getSchemaRegistry().getUrl());
      cfg.put(
          AbstractKafkaSchemaSerDeConfig.AUTO_REGISTER_SCHEMAS,
          props.getSchemaRegistry().isAutoRegisterSchemas());
      cfg.put(
          AbstractKafkaSchemaSerDeConfig.USE_LATEST_VERSION,
          props.getSchemaRegistry().isUseLatestVersion());
      if (StringUtils.hasText(props.getSchemaRegistry().getBasicAuthUserInfo())) {
        cfg.put(AbstractKafkaSchemaSerDeConfig.BASIC_AUTH_CREDENTIALS_SOURCE, "USER_INFO");
        cfg.put(
            AbstractKafkaSchemaSerDeConfig.USER_INFO_CONFIG,
            props.getSchemaRegistry().getBasicAuthUserInfo());
      }
    }
  }

  private void maybeSecurity(Map<String, Object> cfg) {
    if (props.getSecurity() == null) {
      return;
    }
    VeggieKafkaProperties.Security s = props.getSecurity();
    if (StringUtils.hasText(s.getProtocol())) {
      cfg.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, s.getProtocol());
    }
    if (StringUtils.hasText(s.getSaslMechanism())) {
      cfg.put(SaslConfigs.SASL_MECHANISM, s.getSaslMechanism());
    }
    if (StringUtils.hasText(s.getSaslJaas())) {
      cfg.put(SaslConfigs.SASL_JAAS_CONFIG, s.getSaslJaas());
    }
    if (StringUtils.hasText(s.getSslEndpointIdentificationAlgorithm())) {
      cfg.put("ssl.endpoint.identification.algorithm", s.getSslEndpointIdentificationAlgorithm());
    }
  }

  private List<String> bootstrapServers() {
    List<String> bs = props.getBootstrapServers();
    if (bs != null && !bs.isEmpty()) {
      return bs;
    }
    return springKafka.getBootstrapServers();
  }

  private String buildClientId() {
    String app =
        environment != null
            ? environment.getProperty("spring.application.name", "veggieshop")
            : "veggieshop";
    String host;
    try {
      host = InetAddress.getLocalHost().getHostName();
    } catch (Exception e) {
      host = "unknown";
    }
    return app + "-" + host + "-" + Integer.toHexString(ThreadLocalRandom.current().nextInt());
  }

  // ========= Custom properties =========
  @ConfigurationProperties(prefix = "veggieshop.kafka")
  @SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
  public static class VeggieKafkaProperties {

    private List<String> bootstrapServers = new ArrayList<>();
    private final Producer producer = new Producer();
    private final Consumer consumer = new Consumer();
    private final SchemaRegistry schemaRegistry = new SchemaRegistry();
    private final Security security = new Security();
    private String dltSuffix = ".DLQ";

    public List<String> getBootstrapServers() {
      return Collections.unmodifiableList(bootstrapServers);
    }

    public void setBootstrapServers(List<String> bootstrapServers) {
      this.bootstrapServers =
          (bootstrapServers == null) ? new ArrayList<>() : new ArrayList<>(bootstrapServers);
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public Producer getProducer() {
      return producer;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public Consumer getConsumer() {
      return consumer;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public SchemaRegistry getSchemaRegistry() {
      return schemaRegistry;
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public Security getSecurity() {
      return security;
    }

    public String getDltSuffix() {
      return dltSuffix;
    }

    public void setDltSuffix(String dltSuffix) {
      this.dltSuffix = dltSuffix;
    }

    @SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
    public static class Producer {
      private String acks = "all";
      private String compression = "zstd";
      private Duration linger = Duration.ofMillis(5);
      private DataSize batchSize = DataSize.ofKilobytes(64);
      private Duration requestTimeout = Duration.ofSeconds(30);
      private Duration deliveryTimeout = Duration.ofSeconds(120);
      private String transactionalIdPrefix;

      public String getAcks() {
        return acks;
      }

      public void setAcks(String acks) {
        this.acks = acks;
      }

      public String getCompression() {
        return compression;
      }

      public void setCompression(String compression) {
        this.compression = compression;
      }

      public Duration getLinger() {
        return linger;
      }

      public void setLinger(Duration linger) {
        this.linger = linger;
      }

      public DataSize getBatchSize() {
        return batchSize;
      }

      public void setBatchSize(DataSize batchSize) {
        this.batchSize = batchSize;
      }

      public Duration getRequestTimeout() {
        return requestTimeout;
      }

      public void setRequestTimeout(Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
      }

      public Duration getDeliveryTimeout() {
        return deliveryTimeout;
      }

      public void setDeliveryTimeout(Duration deliveryTimeout) {
        this.deliveryTimeout = deliveryTimeout;
      }

      public String getTransactionalIdPrefix() {
        return transactionalIdPrefix;
      }

      public void setTransactionalIdPrefix(String transactionalIdPrefix) {
        this.transactionalIdPrefix = transactionalIdPrefix;
      }
    }

    @SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
    public static class Consumer {
      private int concurrency = 3;
      private String autoOffsetReset = "latest";
      private int maxPollRecords = 500;
      private Duration maxPollInterval = Duration.ofMinutes(5);
      private Duration sessionTimeout = Duration.ofSeconds(45);
      private Duration heartbeatInterval = Duration.ofSeconds(3);
      private Duration fetchMaxWait = Duration.ofMillis(500);
      private Duration pollTimeout = Duration.ofSeconds(2);
      private int maxRetries = 5;
      private Duration retryBackoff = Duration.ofMillis(250);
      private double retryMultiplier = 2.0;
      private Duration maxRetryBackoff = Duration.ofSeconds(3);
      private org.springframework.kafka.listener.ContainerProperties.AckMode ackMode =
          org.springframework.kafka.listener.ContainerProperties.AckMode.MANUAL;

      private List<Class<? extends Exception>> fatalExceptions =
          new ArrayList<>(List.of(IllegalArgumentException.class));

      public int getConcurrency() {
        return concurrency;
      }

      public void setConcurrency(int concurrency) {
        this.concurrency = concurrency;
      }

      public String getAutoOffsetReset() {
        return autoOffsetReset;
      }

      public void setAutoOffsetReset(String autoOffsetReset) {
        this.autoOffsetReset = autoOffsetReset;
      }

      public int getMaxPollRecords() {
        return maxPollRecords;
      }

      public void setMaxPollRecords(int maxPollRecords) {
        this.maxPollRecords = maxPollRecords;
      }

      public Duration getMaxPollInterval() {
        return maxPollInterval;
      }

      public void setMaxPollInterval(Duration maxPollInterval) {
        this.maxPollInterval = maxPollInterval;
      }

      public Duration getSessionTimeout() {
        return sessionTimeout;
      }

      public void setSessionTimeout(Duration sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
      }

      public Duration getHeartbeatInterval() {
        return heartbeatInterval;
      }

      public void setHeartbeatInterval(Duration heartbeatInterval) {
        this.heartbeatInterval = heartbeatInterval;
      }

      public Duration getFetchMaxWait() {
        return fetchMaxWait;
      }

      public void setFetchMaxWait(Duration fetchMaxWait) {
        this.fetchMaxWait = fetchMaxWait;
      }

      public Duration getPollTimeout() {
        return pollTimeout;
      }

      public void setPollTimeout(Duration pollTimeout) {
        this.pollTimeout = pollTimeout;
      }

      public int getMaxRetries() {
        return maxRetries;
      }

      public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
      }

      public Duration getRetryBackoff() {
        return retryBackoff;
      }

      public void setRetryBackoff(Duration retryBackoff) {
        this.retryBackoff = retryBackoff;
      }

      public double getRetryMultiplier() {
        return retryMultiplier;
      }

      public void setRetryMultiplier(double retryMultiplier) {
        this.retryMultiplier = retryMultiplier;
      }

      public Duration getMaxRetryBackoff() {
        return maxRetryBackoff;
      }

      public void setMaxRetryBackoff(Duration maxRetryBackoff) {
        this.maxRetryBackoff = maxRetryBackoff;
      }

      public org.springframework.kafka.listener.ContainerProperties.AckMode getAckMode() {
        return ackMode;
      }

      public void setAckMode(
          org.springframework.kafka.listener.ContainerProperties.AckMode ackMode) {
        this.ackMode = ackMode;
      }

      public List<Class<? extends Exception>> getFatalExceptions() {
        return Collections.unmodifiableList(fatalExceptions);
      }

      public void setFatalExceptions(List<Class<? extends Exception>> fatalExceptions) {
        this.fatalExceptions =
            (fatalExceptions == null) ? new ArrayList<>() : new ArrayList<>(fatalExceptions);
      }
    }

    @SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
    public static class SchemaRegistry {
      private String url;
      private boolean autoRegisterSchemas = false;
      private boolean useLatestVersion = false;
      private String basicAuthUserInfo;

      public String getUrl() {
        return url;
      }

      public void setUrl(String url) {
        this.url = url;
      }

      public boolean isAutoRegisterSchemas() {
        return autoRegisterSchemas;
      }

      public void setAutoRegisterSchemas(boolean autoRegisterSchemas) {
        this.autoRegisterSchemas = autoRegisterSchemas;
      }

      public boolean isUseLatestVersion() {
        return useLatestVersion;
      }

      public void setUseLatestVersion(boolean useLatestVersion) {
        this.useLatestVersion = useLatestVersion;
      }

      public String getBasicAuthUserInfo() {
        return basicAuthUserInfo;
      }

      public void setBasicAuthUserInfo(String basicAuthUserInfo) {
        this.basicAuthUserInfo = basicAuthUserInfo;
      }
    }

    @SuppressWarnings({"checkstyle:MissingJavadocType", "checkstyle:MissingJavadocMethod"})
    public static class Security {
      private String protocol;
      private String saslMechanism;
      private String saslJaas;
      private String sslEndpointIdentificationAlgorithm = "https";

      public String getProtocol() {
        return protocol;
      }

      public void setProtocol(String protocol) {
        this.protocol = protocol;
      }

      public String getSaslMechanism() {
        return saslMechanism;
      }

      public void setSaslMechanism(String saslMechanism) {
        this.saslMechanism = saslMechanism;
      }

      public String getSaslJaas() {
        return saslJaas;
      }

      public void setSaslJaas(String saslJaas) {
        this.saslJaas = saslJaas;
      }

      public String getSslEndpointIdentificationAlgorithm() {
        return sslEndpointIdentificationAlgorithm;
      }

      public void setSslEndpointIdentificationAlgorithm(String sslEndpointIdentificationAlgorithm) {
        this.sslEndpointIdentificationAlgorithm = sslEndpointIdentificationAlgorithm;
      }
    }
  }
}
