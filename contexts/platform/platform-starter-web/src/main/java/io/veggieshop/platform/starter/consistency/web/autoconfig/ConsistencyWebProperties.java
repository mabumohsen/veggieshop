package io.veggieshop.platform.starter.consistency.web.autoconfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Web-layer consistency properties.
 *
 * <p>Master toggle:
 *
 * <pre>
 * veggieshop.web.consistency.enabled=true
 * </pre>
 *
 * <p>Precondition interceptor:
 *
 * <pre>
 * veggieshop.web.consistency.precondition.enabled=true
 * veggieshop.web.consistency.precondition.include-path-patterns[0]=/api/**
 * veggieshop.web.consistency.precondition.exclude-path-patterns[0]=/actuator/**
 * </pre>
 *
 * <p>Headers interceptor:
 *
 * <pre>
 * veggieshop.web.consistency.headers.enabled=true
 * veggieshop.web.consistency.headers.include-path-patterns[0]=/api/**
 * veggieshop.web.consistency.headers.exclude-path-patterns[0]=/actuator/**
 * </pre>
 *
 * <p>ETag advice:
 *
 * <pre>
 * veggieshop.web.consistency.etag.enabled=true
 * </pre>
 */
@Validated
@ConfigurationProperties(prefix = "veggieshop.web.consistency")
public class ConsistencyWebProperties {

  /** Master toggle for all web consistency features. */
  private boolean enabled = true;

  /** Precondition interceptor (If-Consistent-With / If-Match). */
  private final Section precondition = new Section(true);

  /** Headers interceptor (Vary + X-Consistency-Token). */
  private final Section headers = new Section(true);

  /** ETag response advice. */
  private final EtagSection etag = new EtagSection(true);

  // ---------------------------------------------------------------------------------------------
  // Nested types
  // ---------------------------------------------------------------------------------------------

  /**
   * A section of path-based configuration for interceptors. Provides defensive copies to avoid
   * exposing internal state.
   */
  public static class Section {
    private boolean enabled;
    private List<String> includePathPatterns = new ArrayList<>();
    private List<String> excludePathPatterns = defaultExcludes();

    public Section(boolean enabled) {
      this.enabled = enabled;
    }

    /** Defensive copy constructor. */
    public Section(Section other) {
      this.enabled = other.enabled;
      this.includePathPatterns = new ArrayList<>(other.includePathPatterns);
      this.excludePathPatterns = new ArrayList<>(other.excludePathPatterns);
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public List<String> getIncludePathPatterns() {
      return Collections.unmodifiableList(includePathPatterns);
    }

    public void setIncludePathPatterns(List<String> includePathPatterns) {
      this.includePathPatterns =
          (includePathPatterns == null) ? new ArrayList<>() : new ArrayList<>(includePathPatterns);
    }

    public List<String> getExcludePathPatterns() {
      return Collections.unmodifiableList(excludePathPatterns);
    }

    public void setExcludePathPatterns(List<String> excludePathPatterns) {
      this.excludePathPatterns =
          (excludePathPatterns == null) ? new ArrayList<>() : new ArrayList<>(excludePathPatterns);
    }
  }

  /** Toggle for ETag response advice. Provides a defensive copy constructor. */
  public static class EtagSection {
    private boolean enabled;

    public EtagSection(boolean enabled) {
      this.enabled = enabled;
    }

    /** Defensive copy constructor. */
    public EtagSection(EtagSection other) {
      this.enabled = other.enabled;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Defaults
  // ---------------------------------------------------------------------------------------------

  private static List<String> defaultExcludes() {
    List<String> list = new ArrayList<>();
    list.add("/error");
    list.add("/favicon.ico");
    // Typically skip actuator/static assets by default (can be overridden).
    list.add("/actuator/**");
    list.add("/assets/**");
    list.add("/static/**");
    return list;
  }

  // ---------------------------------------------------------------------------------------------
  // Getters / Setters
  // ---------------------------------------------------------------------------------------------

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  /** Returns a defensive copy to avoid exposing internal state. */
  public Section getPrecondition() {
    return new Section(precondition);
  }

  /** Returns a defensive copy to avoid exposing internal state. */
  public Section getHeaders() {
    return new Section(headers);
  }

  /** Returns a defensive copy to avoid exposing internal state. */
  public EtagSection getEtag() {
    return new EtagSection(etag);
  }
}
