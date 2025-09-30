package io.veggieshop.platform.starter.search;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.message.BasicHeader;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.rest_client.RestClientTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for OpenSearch client (low-level RestClient + transport + high-level client).
 * Relies on {@link VeggieOpenSearchProperties} for endpoints, timeouts, auth, and SSL.
 */
@AutoConfiguration
@EnableConfigurationProperties(VeggieOpenSearchProperties.class)
@ConditionalOnClass(OpenSearchClient.class)
public class VeggieOpenSearchAutoConfiguration {
  private static final Logger log =
      LoggerFactory.getLogger(VeggieOpenSearchAutoConfiguration.class);

  @Bean(destroyMethod = "close")
  @ConditionalOnMissingBean
  RestClient osLowLevel(VeggieOpenSearchProperties p) {
    if (p.getEndpoints() == null || p.getEndpoints().isEmpty()) {
      throw new IllegalStateException(
          "OpenSearch endpoints are not configured (veggieshop.search.endpoints)");
    }

    List<HttpHost> hosts = new ArrayList<>();
    for (String ep : p.getEndpoints()) {
      hosts.add(HttpHost.create(ep));
    }

    RestClientBuilder builder =
        RestClient.builder(hosts.toArray(new HttpHost[0]))
            .setRequestConfigCallback(
                cfg ->
                    cfg.setConnectTimeout(toMs(p.getConnectTimeout()))
                        .setSocketTimeout(toMs(p.getSocketTimeout()))
                        .setConnectionRequestTimeout(toMs(p.getConnectionRequestTimeout())))
            .setHttpClientConfigCallback(
                http -> {
                  http.disableAuthCaching();
                  http.setMaxConnPerRoute(p.getMaxConnPerRoute());
                  http.setMaxConnTotal(p.getMaxConnTotal());

                  SSLContext ssl = sslContext(p);
                  if (ssl != null) {
                    http.setSSLContext(ssl);
                  }

                  List<Header> headers = new ArrayList<>();
                  var auth = p.getAuth();
                  if (auth != null && auth.getType() != null) {
                    switch (auth.getType()) {
                      case NONE -> {
                        // no-op
                      }
                      case BASIC -> {
                        String token =
                            Base64.getEncoder()
                                .encodeToString(
                                    (auth.getUsername() + ":" + auth.getPassword())
                                        .getBytes(StandardCharsets.UTF_8));
                        headers.add(new BasicHeader("Authorization", "Basic " + token));
                      }
                      case BEARER -> {
                        headers.add(
                            new BasicHeader("Authorization", "Bearer " + auth.getBearerToken()));
                      }
                      default -> {
                        log.warn("Unknown OpenSearch auth type: {}", auth.getType());
                      }
                    }
                  }
                  if (!headers.isEmpty()) {
                    http.setDefaultHeaders(headers);
                  }
                  return http;
                });

    return builder.build();
  }

  @Bean(destroyMethod = "close")
  @ConditionalOnMissingBean
  OpenSearchTransport osTransport(RestClient lowLevel) {
    return new RestClientTransport(lowLevel, new JacksonJsonpMapper());
  }

  @Bean
  @ConditionalOnMissingBean
  OpenSearchClient openSearchClient(OpenSearchTransport transport) {
    return new OpenSearchClient(transport);
  }

  private static int toMs(Duration d) {
    return Math.toIntExact(d.toMillis());
  }

  /**
   * Builds an {@link SSLContext} from a provided truststore when SSL is enabled. Returns {@code
   * null} if SSL is disabled or truststore is not configured.
   */
  private static SSLContext sslContext(VeggieOpenSearchProperties p) {
    try {
      var truststorePath = p.getTruststorePath(); // store once to satisfy SpotBugs dataflow
      if (!p.isSslEnabled() || truststorePath == null) {
        return null;
      }

      KeyStore ts = KeyStore.getInstance("JKS");
      var truststorePassword = p.getTruststorePassword(); // store once to satisfy SpotBugs

      try (var in = truststorePath.getInputStream()) {
        ts.load(in, truststorePassword != null ? truststorePassword.toCharArray() : null);
      }

      TrustManagerFactory tmf =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(ts);

      SSLContext ctx = SSLContext.getInstance("TLS");
      ctx.init(null, tmf.getTrustManagers(), null);
      return ctx;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to init OpenSearch SSL context", e);
    }
  }
}
