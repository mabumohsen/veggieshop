package io.veggieshop.platform.infrastructure.search;

import org.opensearch.client.Request;
import org.opensearch.client.RestClient;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Pattern;

public final class OpenSearchTenancyScaffolder {
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy.MM.dd");
    private static final Pattern TENANT_ID = Pattern.compile("^[a-z0-9_-]{1,64}$");

    private OpenSearchTenancyScaffolder() {}

    public static String aliasName(String tenantId, String domain){ return "tenant-" + v(tenantId) + "-" + domain; }
    public static String indexPattern(String tenantId, String domain){ return "tenant-" + v(tenantId) + "-" + domain + "-*"; }
    public static String firstIndexName(String tenantId, String domain){ return "tenant-" + v(tenantId) + "-" + domain + "-000001"; }
    public static String dateIndex(String tenantId, String domain, LocalDate date){ return "tenant-" + v(tenantId) + "-" + domain + "-" + DATE.format(date); }
    public static String templateName(String tenantId, String domain){ return "tpl-tenant-" + v(tenantId) + "-" + domain; }
    public static String policyName(String tenantId, String domain){ return "pol-tenant-" + v(tenantId) + "-" + domain; }

    public static void ensureTenantScaffolding(RestClient low,
                                               VeggieOsIlmSettings s,
                                               String tenantId, String domain) throws IOException {
        String t = v(tenantId);
        String policy = policyName(t, domain);
        String template = templateName(t, domain);
        String pattern = indexPattern(t, domain);
        String alias = aliasName(t, domain);

        upsertIsmPolicy(low, policy, s);
        upsertTemplate(low, template, pattern, alias, policy, s);
        createBootstrapIndexIfMissing(low, firstIndexName(t, domain), alias);
    }

    private static String v(String tenantId){
        String t = tenantId.trim().toLowerCase(Locale.ROOT);
        if (!TENANT_ID.matcher(t).matches()) throw new IllegalArgumentException("Invalid tenantId");
        return t;
    }

    private static void upsertIsmPolicy(RestClient low, String policy, VeggieOsIlmSettings s) throws IOException {
        String json = """
                {"policy":{"description":"VeggieShop tenant policy","default_state":"hot",
                 "ism_template":[],"states":[
                   {"name":"hot","actions":[{"rollover":{"min_size":"%s","min_index_age":"%s"}}],
                    "transitions":[{"state_name":"delete","conditions":{"min_index_age":"%s"}}]},
                   {"name":"delete","actions":[{"delete":{}}],"transitions":[]}]}}
                """.formatted(s.rolloverMaxSize(), s.rolloverMaxAge(), s.retentionMaxAge());
        Request req = new Request("PUT", "/_plugins/_ism/policies/" + policy);
        req.setJsonEntity(json);
        low.performRequest(req);
    }

    private static void upsertTemplate(RestClient low, String name, String pattern, String alias,
                                       String policy, VeggieOsIlmSettings s) throws IOException {
        String json = """
                {"index_patterns":["%s"],
                 "template":{"settings":{
                   "index.number_of_shards":%d,"index.number_of_replicas":%d,
                   "index.refresh_interval":"%s",
                   "index.routing.allocation.require._tier_preference":"%s",
                   "index.plugins.index_state_management.policy_id":"%s",
                   "index.codec":"best_compression"},
                   "mappings":{"_source":{"enabled":true},"dynamic":"false"},
                   "aliases":{"%s":{"is_write_index":true}}},
                 "priority":%d,"version":%d}
                """.formatted(pattern, s.shards(), s.replicas(),
                s.refreshInterval(), s.preferredTier(), policy, alias,
                s.templatePriority(), s.templateVersion());
        Request req = new Request("PUT", "/_index_template/" + name);
        req.setJsonEntity(json);
        low.performRequest(req);
    }

    private static void createBootstrapIndexIfMissing(RestClient low, String index, String alias) throws IOException {
        try {
            if (low.performRequest(new Request("HEAD", "/" + index))
                    .getStatusLine().getStatusCode() == 200) return;
        } catch (org.opensearch.client.ResponseException ignore) { /* not found → create */ }

        Request put = new Request("PUT", "/" + index);
        // إما Text Block صحيح...
        put.setJsonEntity(("""
                { "aliases": { "%s": { "is_write_index": true } } }
                """).formatted(alias));
        low.performRequest(put);
    }

    /** ضبط ILM مبسّط يمرّره النداء. */
    public record VeggieOsIlmSettings(
            String rolloverMaxSize, String rolloverMaxAge, String retentionMaxAge,
            int shards, int replicas, String refreshInterval, String preferredTier,
            int templatePriority, int templateVersion) {}
}
