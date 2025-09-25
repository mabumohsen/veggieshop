package io.veggieshop.platform.starter.search;

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

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@AutoConfiguration
@EnableConfigurationProperties(VeggieOpenSearchProperties.class)
@ConditionalOnClass(OpenSearchClient.class)
public class VeggieOpenSearchAutoConfiguration {
    private static final Logger log = LoggerFactory.getLogger(VeggieOpenSearchAutoConfiguration.class);

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    RestClient osLowLevel(VeggieOpenSearchProperties p) {
        if (p.getEndpoints() == null || p.getEndpoints().isEmpty()) {
            throw new IllegalStateException("OpenSearch endpoints are not configured (veggieshop.search.endpoints)");
        }
        List<HttpHost> hosts = new ArrayList<>();
        for (String ep : p.getEndpoints()) hosts.add(HttpHost.create(ep));

        RestClientBuilder builder = RestClient.builder(hosts.toArray(HttpHost[]::new))
                .setRequestConfigCallback(cfg -> cfg
                        .setConnectTimeout(toMs(p.getConnectTimeout()))
                        .setSocketTimeout(toMs(p.getSocketTimeout()))
                        .setConnectionRequestTimeout(toMs(p.getConnectionRequestTimeout()))
                )
                .setHttpClientConfigCallback(http -> {
                    http.disableAuthCaching();
                    http.setMaxConnPerRoute(p.getMaxConnPerRoute());
                    http.setMaxConnTotal(p.getMaxConnTotal());

                    SSLContext ssl = sslContext(p);
                    if (ssl != null) http.setSSLContext(ssl);

                    List<Header> headers = new ArrayList<>();
                    var auth = p.getAuth();
                    if (auth != null && auth.getType() != null) {
                        switch (auth.getType()) {
                            case NONE -> { /* no-op */ }
                            case BASIC -> {
                                String token = Base64.getEncoder().encodeToString(
                                        (auth.getUsername() + ":" + auth.getPassword()).getBytes(StandardCharsets.UTF_8));
                                headers.add(new BasicHeader("Authorization", "Basic " + token));
                            }
                            case BEARER -> headers.add(new BasicHeader("Authorization", "Bearer " + auth.getBearerToken()));
                        }
                    }
                    if (!headers.isEmpty()) http.setDefaultHeaders(headers);
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

    private static int toMs(Duration d){ return Math.toIntExact(d.toMillis()); }

    private static SSLContext sslContext(VeggieOpenSearchProperties p) {
        try {
            if (!p.isSslEnabled() || p.getTruststorePath() == null) return null;
            KeyStore ts = KeyStore.getInstance("JKS");
            try (var in = p.getTruststorePath().getInputStream()) {
                ts.load(in, p.getTruststorePassword() != null ? p.getTruststorePassword().toCharArray() : null);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to init OpenSearch SSL context", e);
        }
    }
}
