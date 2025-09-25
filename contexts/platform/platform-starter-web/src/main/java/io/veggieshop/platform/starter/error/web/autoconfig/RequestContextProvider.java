package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.problem.core.RequestContext;
import jakarta.servlet.http.HttpServletRequest;

public interface RequestContextProvider {
    RequestContext from(HttpServletRequest req);
}
