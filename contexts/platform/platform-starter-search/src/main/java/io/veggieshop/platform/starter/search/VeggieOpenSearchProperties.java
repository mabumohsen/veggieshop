package io.veggieshop.platform.starter.search;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "veggieshop.search")
public class VeggieOpenSearchProperties {

    private List<String> endpoints = List.of("http://localhost:9200");

    private boolean sslEnabled = true;
    @Nullable
    private Resource truststorePath;
    @Nullable
    private String truststorePassword;

    private Duration connectTimeout = Duration.ofMillis(500);
    private Duration socketTimeout = Duration.ofSeconds(3);
    private Duration connectionRequestTimeout = Duration.ofSeconds(2);
    private int maxConnTotal = 200;
    private int maxConnPerRoute = 100;

    public static final class Auth {
        public enum Type { NONE, BASIC, BEARER }
        private Type type = Type.NONE;
        @Nullable private String username;
        @Nullable private String password;
        @Nullable private String bearerToken;

        public Type getType() { return type; }
        public void setType(Type type) { this.type = type; }
        @Nullable public String getUsername() { return username; }
        public void setUsername(@Nullable String username) { this.username = username; }
        @Nullable public String getPassword() { return password; }
        public void setPassword(@Nullable String password) { this.password = password; }
        @Nullable public String getBearerToken() { return bearerToken; }
        public void setBearerToken(@Nullable String bearerToken) { this.bearerToken = bearerToken; }
    }
    private Auth auth = new Auth();

    private String refreshInterval = "1s";
    private String preferredTier = "data_content";
    private int templatePriority = 500;
    private int templateVersion = 1;

    public static final class Ilm {
        private String rolloverMaxSize;
        private String rolloverMaxAge;
        private String retentionMaxAge;
        private int shards;
        private int replicas;

        public static Ilm standardDefault() {
            Ilm i = new Ilm();
            i.rolloverMaxSize = "50gb";
            i.rolloverMaxAge  = "7d";
            i.retentionMaxAge = "30d";
            i.shards = 1;
            i.replicas = 1;
            return i;
        }
        public static Ilm enterpriseDefault() {
            Ilm i = new Ilm();
            i.rolloverMaxSize = "100gb";
            i.rolloverMaxAge  = "7d";
            i.retentionMaxAge = "90d";
            i.shards = 3;
            i.replicas = 1;
            return i;
        }

        public String getRolloverMaxSize() { return rolloverMaxSize; }
        public void setRolloverMaxSize(String rolloverMaxSize) { this.rolloverMaxSize = rolloverMaxSize; }
        public String getRolloverMaxAge() { return rolloverMaxAge; }
        public void setRolloverMaxAge(String rolloverMaxAge) { this.rolloverMaxAge = rolloverMaxAge; }
        public String getRetentionMaxAge() { return retentionMaxAge; }
        public void setRetentionMaxAge(String retentionMaxAge) { this.retentionMaxAge = retentionMaxAge; }
        public int getShards() { return shards; }
        public void setShards(int shards) { this.shards = shards; }
        public int getReplicas() { return replicas; }
        public void setReplicas(int replicas) { this.replicas = replicas; }
    }
    private Ilm standard = Ilm.standardDefault();
    private Ilm enterprise = Ilm.enterpriseDefault();

    public enum Tier { STANDARD, ENTERPRISE }

    // convenience getters by tier
    public String getRolloverMaxSize(Tier t){ return t==Tier.ENTERPRISE ? enterprise.getRolloverMaxSize() : standard.getRolloverMaxSize(); }
    public String getRolloverMaxAge(Tier t){  return t==Tier.ENTERPRISE ? enterprise.getRolloverMaxAge()  : standard.getRolloverMaxAge(); }
    public String getRetentionMaxAge(Tier t){ return t==Tier.ENTERPRISE ? enterprise.getRetentionMaxAge() : standard.getRetentionMaxAge(); }
    public int getShards(Tier t){            return t==Tier.ENTERPRISE ? enterprise.getShards()           : standard.getShards(); }
    public int getReplicas(Tier t){          return t==Tier.ENTERPRISE ? enterprise.getReplicas()         : standard.getReplicas(); }

    // ---- getters/setters لكل الحقول أعلاه ----
    public List<String> getEndpoints() { return endpoints; }
    public void setEndpoints(List<String> endpoints) { this.endpoints = endpoints; }

    public boolean isSslEnabled() { return sslEnabled; }
    public void setSslEnabled(boolean sslEnabled) { this.sslEnabled = sslEnabled; }

    @Nullable public Resource getTruststorePath() { return truststorePath; }
    public void setTruststorePath(@Nullable Resource truststorePath) { this.truststorePath = truststorePath; }

    @Nullable public String getTruststorePassword() { return truststorePassword; }
    public void setTruststorePassword(@Nullable String truststorePassword) { this.truststorePassword = truststorePassword; }

    public Duration getConnectTimeout() { return connectTimeout; }
    public void setConnectTimeout(Duration connectTimeout) { this.connectTimeout = connectTimeout; }

    public Duration getSocketTimeout() { return socketTimeout; }
    public void setSocketTimeout(Duration socketTimeout) { this.socketTimeout = socketTimeout; }

    public Duration getConnectionRequestTimeout() { return connectionRequestTimeout; }
    public void setConnectionRequestTimeout(Duration connectionRequestTimeout) { this.connectionRequestTimeout = connectionRequestTimeout; }

    public int getMaxConnTotal() { return maxConnTotal; }
    public void setMaxConnTotal(int maxConnTotal) { this.maxConnTotal = maxConnTotal; }

    public int getMaxConnPerRoute() { return maxConnPerRoute; }
    public void setMaxConnPerRoute(int maxConnPerRoute) { this.maxConnPerRoute = maxConnPerRoute; }

    public Auth getAuth() { return auth; }
    public void setAuth(Auth auth) { this.auth = auth; }

    public String getRefreshInterval() { return refreshInterval; }
    public void setRefreshInterval(String refreshInterval) { this.refreshInterval = refreshInterval; }

    public String getPreferredTier() { return preferredTier; }
    public void setPreferredTier(String preferredTier) { this.preferredTier = preferredTier; }

    public int getTemplatePriority() { return templatePriority; }
    public void setTemplatePriority(int templatePriority) { this.templatePriority = templatePriority; }

    public int getTemplateVersion() { return templateVersion; }
    public void setTemplateVersion(int templateVersion) { this.templateVersion = templateVersion; }

    public Ilm getStandard() { return standard; }
    public void setStandard(Ilm standard) { this.standard = standard; }

    public Ilm getEnterprise() { return enterprise; }
    public void setEnterprise(Ilm enterprise) { this.enterprise = enterprise; }
}
