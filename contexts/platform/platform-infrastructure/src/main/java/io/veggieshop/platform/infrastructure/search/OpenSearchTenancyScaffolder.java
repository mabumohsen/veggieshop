package io.veggieshop.platform.infrastructure.search;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Pattern;
import org.opensearch.client.Request;
import org.opensearch.client.RestClient;

/**
 * Utilities to scaffold per-tenant OpenSearch assets (ISM policy, index template, bootstrap index +
 * write alias) following the naming convention:
 *
 * <pre>
 * alias:        tenant-{tenantId}-{domain}
 * index:        tenant-{tenantId}-{domain}-000001
 * index-dated:  tenant-{tenantId}-{domain}-yyyy.MM.dd
 * template:     tpl-tenant-{tenantId}-{domain}
 * policy:       pol-tenant-{tenantId}-{domain}
 * </pre>
 *
 * <p>All methods validate tenantId using {@code ^[a-z0-9_-]{1,64}$} and lowercase it.
 */
public final class OpenSearchTenancyScaffolder {

  private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy.MM.dd");
  private static final Pattern TENANT_ID = Pattern.compile("^[a-z0-9_-]{1,64}$");

  private OpenSearchTenancyScaffolder() {}

  /** Write alias: {@code tenant-{tenantId}-{domain}}. */
  public static String aliasName(String tenantId, String domain) {
    return "tenant-" + normalizeTenantId(tenantId) + "-" + domain;
  }

  /** Index pattern: {@code tenant-{tenantId}-{domain}-*}. */
  public static String indexPattern(String tenantId, String domain) {
    return "tenant-" + normalizeTenantId(tenantId) + "-" + domain + "-*";
  }

  /** First concrete index for a data stream/rollover: suffix {@code -000001}. */
  public static String firstIndexName(String tenantId, String domain) {
    return "tenant-" + normalizeTenantId(tenantId) + "-" + domain + "-000001";
  }

  /** Dated index name: suffix {@code -yyyy.MM.dd}. */
  public static String dateIndex(String tenantId, String domain, LocalDate date) {
    return "tenant-" + normalizeTenantId(tenantId) + "-" + domain + "-" + DATE.format(date);
  }

  /** Index template name. */
  public static String templateName(String tenantId, String domain) {
    return "tpl-tenant-" + normalizeTenantId(tenantId) + "-" + domain;
  }

  /** ISM policy name. */
  public static String policyName(String tenantId, String domain) {
    return "pol-tenant-" + normalizeTenantId(tenantId) + "-" + domain;
  }

  /**
   * Ensure that ISM policy, index template and bootstrap index exist for a tenant/domain.
   * Creates/updates policy and template, and creates a first index if missing.
   */
  public static void ensureTenantScaffolding(
      RestClient low, VeggieOsIlmSettings s, String tenantId, String domain) throws IOException {

    String t = normalizeTenantId(tenantId);
    String policy = policyName(t, domain);
    String template = templateName(t, domain);
    String pattern = indexPattern(t, domain);
    String alias = aliasName(t, domain);

    upsertIsmPolicy(low, policy, s);
    upsertTemplate(low, template, pattern, alias, policy, s);
    createBootstrapIndexIfMissing(low, firstIndexName(t, domain), alias);
  }

  /** Normalize and validate tenant id (lowercase, pattern-checked). */
  private static String normalizeTenantId(String tenantId) {
    String t = tenantId.trim().toLowerCase(Locale.ROOT);
    if (!TENANT_ID.matcher(t).matches()) {
      throw new IllegalArgumentException("Invalid tenantId");
    }
    return t;
  }

  /** PUT/UPSERT an ISM policy for the tenant. */
  private static void upsertIsmPolicy(RestClient low, String policy, VeggieOsIlmSettings s)
      throws IOException {

    String json =
        """
      { "policy": {
        "description": "VeggieShop tenant policy",
        "default_state": "hot",
        "ism_template": [],
        "states": [
          {
            "name": "hot",
            "actions": [
              { "rollover": { "min_size": "__MAX_SIZE__", "min_index_age": "__MAX_AGE__" } }
            ],
            "transitions": [
              { "state_name": "delete", "conditions": { "min_index_age": "__RETENTION__" } }
            ]
          },
          {
            "name": "delete",
            "actions": [ { "delete": {} } ],
            "transitions": []
          }
        ]
      } }
      """
            .replace("__MAX_SIZE__", s.rolloverMaxSize())
            .replace("__MAX_AGE__", s.rolloverMaxAge())
            .replace("__RETENTION__", s.retentionMaxAge());

    Request req = new Request("PUT", "/_plugins/_ism/policies/" + policy);
    req.setJsonEntity(json);
    low.performRequest(req);
  }

  /** PUT/UPSERT the index template binding alias and ISM policy. */
  private static void upsertTemplate(
      RestClient low,
      String name,
      String pattern,
      String alias,
      String policy,
      VeggieOsIlmSettings s)
      throws IOException {

    String json =
        ("{%n"
                + "  \"index_patterns\": [\"%s\"],%n"
                + "  \"template\": {%n"
                + "    \"settings\": {%n"
                + "      \"index.number_of_shards\": %d,%n"
                + "      \"index.number_of_replicas\": %d,%n"
                + "      \"index.refresh_interval\": \"%s\",%n"
                + "      \"index.routing.allocation.require._tier_preference\": \"%s\",%n"
                + "      \"index.plugins.index_state_management.policy_id\": \"%s\",%n"
                + "      \"index.codec\": \"best_compression\"%n"
                + "    },%n"
                + "    \"mappings\": {%n"
                + "      \"_source\": {\"enabled\": true},%n"
                + "      \"dynamic\": \"false\"%n"
                + "    },%n"
                + "    \"aliases\": {\"%s\": {\"is_write_index\": true}}%n"
                + "  },%n"
                + "  \"priority\": %d,%n"
                + "  \"version\": %d%n"
                + "}")
            .formatted(
                pattern,
                s.shards(),
                s.replicas(),
                s.refreshInterval(),
                s.preferredTier(),
                policy,
                alias,
                s.templatePriority(),
                s.templateVersion());

    Request req = new Request("PUT", "/_index_template/" + name);
    req.setJsonEntity(json);
    low.performRequest(req);
  }

  /** Create first concrete index if it does not exist, and bind write alias. */
  private static void createBootstrapIndexIfMissing(RestClient low, String index, String alias)
      throws IOException {

    try {
      int code =
          low.performRequest(new Request("HEAD", "/" + index)).getStatusLine().getStatusCode();
      if (code == 200) {
        return;
      }
    } catch (org.opensearch.client.ResponseException ignore) {
      // not found → create
    }

    String json = ("{ \"aliases\": { \"%s\": { \"is_write_index\": true } } }").formatted(alias);

    Request put = new Request("PUT", "/" + index);
    put.setJsonEntity(json);
    low.performRequest(put);
  }

  /** Simple ILM/ISM knobs passed by the caller. */
  public record VeggieOsIlmSettings(
      String rolloverMaxSize,
      String rolloverMaxAge,
      String retentionMaxAge,
      int shards,
      int replicas,
      String refreshInterval,
      String preferredTier,
      int templatePriority,
      int templateVersion) {}
}
