package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.problem.core.RequestContext;
import jakarta.servlet.http.HttpServletRequest;

/** Abstraction that builds a {@link RequestContext} from an incoming HTTP request. */
public interface RequestContextProvider {

  /**
   * Build a {@link RequestContext} for the given request without including PII.
   *
   * @param req the current HTTP request
   * @return a non-null {@link RequestContext} snapshot
   */
  RequestContext from(HttpServletRequest req);
}
