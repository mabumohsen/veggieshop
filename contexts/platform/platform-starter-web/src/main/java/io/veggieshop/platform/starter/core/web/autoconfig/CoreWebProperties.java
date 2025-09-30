package io.veggieshop.platform.starter.core.web.autoconfig;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Prefix: veggieshop.web.core */
@ConfigurationProperties(prefix = "veggieshop.web.core")
public class CoreWebProperties {
  /** Enable ForwardedHeaderFilter behind proxies/LB. */
  private boolean forwardedEnabled = true;

  public boolean isForwardedEnabled() {
    return forwardedEnabled;
  }

  public void setForwardedEnabled(boolean forwardedEnabled) {
    this.forwardedEnabled = forwardedEnabled;
  }
}
