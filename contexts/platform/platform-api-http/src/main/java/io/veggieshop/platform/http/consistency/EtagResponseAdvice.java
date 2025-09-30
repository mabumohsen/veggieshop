package io.veggieshop.platform.http.consistency;

import io.veggieshop.platform.domain.version.ConsistencyStamped;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * Adds a strong ETag header for responses whose body implements {@link ConsistencyStamped}, when
 * the controller didn't already set an ETag. The entity version is also exposed on the underlying
 * {@link HttpServletRequest} as a request attribute so that {@code ConsistencyHeadersInterceptor}
 * can fold it into the emitted {@code X-Consistency-Token}.
 *
 * <p><strong>Registration</strong>: this class intentionally does not carry
 * {@code @ControllerAdvice}. The starter module should register it as a bean.
 *
 * <p><strong>ETag shape</strong>: strong ETag encoded as a quoted hex string of the positive entity
 * version, e.g., {@code "7f2a"}.
 *
 * <p><strong>Notes</strong>:
 *
 * <ul>
 *   <li>No-op if an ETag is already present.
 *   <li>Does not attempt to generate ETags for streaming or non-versioned bodies.
 * </ul>
 *
 * @since 1.0.0
 */
public final class EtagResponseAdvice implements ResponseBodyAdvice<Object> {

  /** Request attribute name that carries the entity version (if available). */
  public static final String ATTR_ENTITY_VERSION =
      EtagResponseAdvice.class.getName() + ".ENTITY_VERSION";

  @Override
  public boolean supports(
      @NonNull final MethodParameter returnType,
      @NonNull final Class<? extends HttpMessageConverter<?>> converterType) {
    return true;
  }

  @Override
  public Object beforeBodyWrite(
      final Object body,
      @NonNull final MethodParameter returnType,
      @NonNull final MediaType selectedContentType,
      @NonNull final Class<? extends HttpMessageConverter<?>> selectedConverterType,
      @NonNull final ServerHttpRequest request,
      @NonNull final ServerHttpResponse response) {

    final HttpHeaders headers = response.getHeaders();

    // Respect an existing ETag set by the controller/other advices.
    if (headers.getETag() != null) {
      if (request instanceof ServletServerHttpRequest servletReq) {
        final HttpServletRequest http = servletReq.getServletRequest();
        http.removeAttribute(ATTR_ENTITY_VERSION);
      }
      return body;
    }

    // Extract a positive entity version when the body exposes one.
    Long version = null;
    if (body instanceof ConsistencyStamped stamped) {
      final var optVersion = stamped.version();
      if (optVersion.isPresent()) {
        final long v = optVersion.get().value(); // unwrap EntityVersion
        if (v > 0) {
          version = v;
        }
      }
    }

    if (version != null) {
      headers.setETag(toStrongEtag(version));
      if (request instanceof ServletServerHttpRequest servletReq) {
        final HttpServletRequest http = servletReq.getServletRequest();
        http.setAttribute(ATTR_ENTITY_VERSION, version);
      }
    } else {
      if (request instanceof ServletServerHttpRequest servletReq) {
        final HttpServletRequest http = servletReq.getServletRequest();
        http.removeAttribute(ATTR_ENTITY_VERSION);
      }
    }

    return body;
  }

  /** Builds a strong (quoted) hex ETag from a positive numeric version. */
  private static String toStrongEtag(final long version) {
    return "\"" + Long.toHexString(version) + "\"";
  }
}
