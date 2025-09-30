package io.veggieshop.platform.starter.search;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.lang.Nullable;

/**
 * Configuration properties for VeggieShop OpenSearch integration. Prefix: {@code veggieshop.search}
 */
@ConfigurationProperties(prefix = "veggieshop.search")
public class VeggieOpenSearchProperties {

  /** OpenSearch endpoints (e.g., http://localhost:9200). */
  private List<String> endpoints = List.of("http://localhost:9200");

  /** Enable SSL/TLS when connecting to OpenSearch. */
  private boolean sslEnabled = true;

  @Nullable private Resource truststorePath;
  @Nullable private String truststorePassword;

  /** HTTP client timeouts and connection pool sizing. */
  private Duration connectTimeout = Duration.ofMillis(500);

  private Duration socketTimeout = Duration.ofSeconds(3);
  private Duration connectionRequestTimeout = Duration.ofSeconds(2);
  private int maxConnTotal = 200;
  private int maxConnPerRoute = 100;

  /**
   * Authentication settings for OpenSearch. Exposed via defensive copies to avoid exposing internal
   * representation.
   */
  public static final class Auth {
    /** Supported authentication types. */
    public enum Type {
      /** No authentication header. */
      NONE,
      /** HTTP Basic (username/password). */
      BASIC,
      /** Bearer token. */
      BEARER
    }

    private Type type = Type.NONE;
    @Nullable private String username;
    @Nullable private String password;
    @Nullable private String bearerToken;

    /** Default constructor. */
    public Auth() {}

    /** Copy constructor. */
    public Auth(Auth other) {
      if (other != null) {
        this.type = other.type;
        this.username = other.username;
        this.password = other.password;
        this.bearerToken = other.bearerToken;
      }
    }

    /** Authentication type. */
    public Type getType() {
      return type;
    }

    /** Set authentication type. */
    public void setType(Type type) {
      this.type = type;
    }

    /** Username for BASIC auth. */
    @Nullable
    public String getUsername() {
      return username;
    }

    /** Set username for BASIC auth. */
    public void setUsername(@Nullable String username) {
      this.username = username;
    }

    /** Password for BASIC auth. */
    @Nullable
    public String getPassword() {
      return password;
    }

    /** Set password for BASIC auth. */
    public void setPassword(@Nullable String password) {
      this.password = password;
    }

    /** Bearer token for BEARER auth. */
    @Nullable
    public String getBearerToken() {
      return bearerToken;
    }

    /** Set bearer token for BEARER auth. */
    public void setBearerToken(@Nullable String bearerToken) {
      this.bearerToken = bearerToken;
    }
  }

  private Auth auth = new Auth();

  /** Index defaults and template settings. */
  private String refreshInterval = "1s";

  private String preferredTier = "data_content";
  private int templatePriority = 500;
  private int templateVersion = 1;

  /**
   * ILM (lifecycle) settings for different tiers. Exposed via defensive copies to avoid exposing
   * internal representation.
   */
  public static final class Ilm {
    private String rolloverMaxSize;
    private String rolloverMaxAge;
    private String retentionMaxAge;
    private int shards;
    private int replicas;

    /** Default constructor. */
    public Ilm() {}

    /** Copy constructor. */
    public Ilm(Ilm other) {
      if (other != null) {
        this.rolloverMaxSize = other.rolloverMaxSize;
        this.rolloverMaxAge = other.rolloverMaxAge;
        this.retentionMaxAge = other.retentionMaxAge;
        this.shards = other.shards;
        this.replicas = other.replicas;
      }
    }

    /**
     * Creates the default ILM settings for the <em>standard</em> tier.
     *
     * @return a new {@code Ilm} with: size=50gb, rollover=7d, retention=30d, shards=1, replicas=1
     */
    public static Ilm standardDefault() {
      Ilm i = new Ilm();
      i.rolloverMaxSize = "50gb";
      i.rolloverMaxAge = "7d";
      i.retentionMaxAge = "30d";
      i.shards = 1;
      i.replicas = 1;
      return i;
    }

    /**
     * Creates the default ILM settings for the <em>enterprise</em> tier.
     *
     * @return a new {@code Ilm} with: size=100gb, rollover=7d, retention=90d, shards=3, replicas=1
     */
    public static Ilm enterpriseDefault() {
      Ilm i = new Ilm();
      i.rolloverMaxSize = "100gb";
      i.rolloverMaxAge = "7d";
      i.retentionMaxAge = "90d";
      i.shards = 3;
      i.replicas = 1;
      return i;
    }

    public String getRolloverMaxSize() {
      return rolloverMaxSize;
    }

    public void setRolloverMaxSize(String rolloverMaxSize) {
      this.rolloverMaxSize = rolloverMaxSize;
    }

    public String getRolloverMaxAge() {
      return rolloverMaxAge;
    }

    public void setRolloverMaxAge(String rolloverMaxAge) {
      this.rolloverMaxAge = rolloverMaxAge;
    }

    public String getRetentionMaxAge() {
      return retentionMaxAge;
    }

    public void setRetentionMaxAge(String retentionMaxAge) {
      this.retentionMaxAge = retentionMaxAge;
    }

    public int getShards() {
      return shards;
    }

    public void setShards(int shards) {
      this.shards = shards;
    }

    public int getReplicas() {
      return replicas;
    }

    public void setReplicas(int replicas) {
      this.replicas = replicas;
    }
  }

  private Ilm standard = Ilm.standardDefault();
  private Ilm enterprise = Ilm.enterpriseDefault();

  /** Named profile for choosing between ILM tiers. */
  public enum Tier {
    STANDARD,
    ENTERPRISE
  }

  // ---------- Convenience getters by tier (read-only) ----------
  public String getRolloverMaxSize(Tier t) {
    return t == Tier.ENTERPRISE ? enterprise.getRolloverMaxSize() : standard.getRolloverMaxSize();
  }

  public String getRolloverMaxAge(Tier t) {
    return t == Tier.ENTERPRISE ? enterprise.getRolloverMaxAge() : standard.getRolloverMaxAge();
  }

  public String getRetentionMaxAge(Tier t) {
    return t == Tier.ENTERPRISE ? enterprise.getRetentionMaxAge() : standard.getRetentionMaxAge();
  }

  public int getShards(Tier t) {
    return t == Tier.ENTERPRISE ? enterprise.getShards() : standard.getShards();
  }

  public int getReplicas(Tier t) {
    return t == Tier.ENTERPRISE ? enterprise.getReplicas() : standard.getReplicas();
  }

  // ---------- Standard getters/setters (مع نسخ دفاعي) ----------
  /** Endpoints list (defensive copy). */
  public List<String> getEndpoints() {
    return endpoints == null ? List.of() : List.copyOf(endpoints);
  }

  /** Set endpoints (defensive copy). */
  public void setEndpoints(List<String> endpoints) {
    this.endpoints = (endpoints == null) ? List.of() : List.copyOf(endpoints);
  }

  public boolean isSslEnabled() {
    return sslEnabled;
  }

  public void setSslEnabled(boolean sslEnabled) {
    this.sslEnabled = sslEnabled;
  }

  @Nullable
  public Resource getTruststorePath() {
    return truststorePath;
  }

  public void setTruststorePath(@Nullable Resource truststorePath) {
    this.truststorePath = truststorePath;
  }

  @Nullable
  public String getTruststorePassword() {
    return truststorePassword;
  }

  public void setTruststorePassword(@Nullable String truststorePassword) {
    this.truststorePassword = truststorePassword;
  }

  public Duration getConnectTimeout() {
    return connectTimeout;
  }

  public void setConnectTimeout(Duration connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  public Duration getSocketTimeout() {
    return socketTimeout;
  }

  public void setSocketTimeout(Duration socketTimeout) {
    this.socketTimeout = socketTimeout;
  }

  public Duration getConnectionRequestTimeout() {
    return connectionRequestTimeout;
  }

  public void setConnectionRequestTimeout(Duration connectionRequestTimeout) {
    this.connectionRequestTimeout = connectionRequestTimeout;
  }

  public int getMaxConnTotal() {
    return maxConnTotal;
  }

  public void setMaxConnTotal(int maxConnTotal) {
    this.maxConnTotal = maxConnTotal;
  }

  public int getMaxConnPerRoute() {
    return maxConnPerRoute;
  }

  public void setMaxConnPerRoute(int maxConnPerRoute) {
    this.maxConnPerRoute = maxConnPerRoute;
  }

  /** Get auth (defensive copy). */
  public Auth getAuth() {
    return new Auth(this.auth);
  }

  /** Set auth (defensive copy). */
  public void setAuth(Auth auth) {
    this.auth = (auth == null) ? new Auth() : new Auth(auth);
  }

  public String getRefreshInterval() {
    return refreshInterval;
  }

  public void setRefreshInterval(String refreshInterval) {
    this.refreshInterval = refreshInterval;
  }

  public String getPreferredTier() {
    return preferredTier;
  }

  public void setPreferredTier(String preferredTier) {
    this.preferredTier = preferredTier;
  }

  public int getTemplatePriority() {
    return templatePriority;
  }

  public void setTemplatePriority(int templatePriority) {
    this.templatePriority = templatePriority;
  }

  public int getTemplateVersion() {
    return templateVersion;
  }

  public void setTemplateVersion(int templateVersion) {
    this.templateVersion = templateVersion;
  }

  /** Get STANDARD ILM (defensive copy). */
  public Ilm getStandard() {
    return new Ilm(this.standard);
  }

  /** Set STANDARD ILM (defensive copy). */
  public void setStandard(Ilm standard) {
    this.standard = (standard == null) ? Ilm.standardDefault() : new Ilm(standard);
  }

  /** Get ENTERPRISE ILM (defensive copy). */
  public Ilm getEnterprise() {
    return new Ilm(this.enterprise);
  }

  /** Set ENTERPRISE ILM (defensive copy). */
  public void setEnterprise(Ilm enterprise) {
    this.enterprise = (enterprise == null) ? Ilm.enterpriseDefault() : new Ilm(enterprise);
  }
}
