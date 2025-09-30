package io.veggieshop.platform.http.error;

import io.veggieshop.problem.core.ProblemPayload;
import java.net.URI;
import java.util.Objects;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;

/**
 * Maps the domain-level {@link ProblemPayload} (framework-agnostic RFC 7807 model) to Spring Web's
 * {@link ProblemDetail}.
 *
 * <p>Design principles:
 *
 * <ul>
 *   <li><strong>Pure mapping only</strong>: no policy changes, no side effects.
 *   <li><strong>Field parity</strong>: {@code type}, {@code title}, {@code status}, {@code detail},
 *       {@code instance}, and {@code extensions} are copied as-is.
 *   <li><strong>Adapter boundary</strong>: intended for the HTTP layer; the domain stays free of
 *       Spring Web types.
 * </ul>
 *
 * <p>Thread-safety: this mapper is stateless and therefore thread-safe.
 */
public final class ProblemHttpMapper {

  /**
   * Converts a {@link ProblemPayload} into a Spring {@link ProblemDetail}.
   *
   * <p>The resulting {@code ProblemDetail} is created via {@link
   * ProblemDetail#forStatusAndDetail(org.springframework.http.HttpStatusCode, String)}, then
   * populated with:
   *
   * <ul>
   *   <li>{@code title} via {@link ProblemDetail#setTitle(String)}
   *   <li>{@code type} via {@link ProblemDetail#setType(URI)}
   *   <li>{@code instance} via {@link ProblemDetail#setInstance(URI)}
   *   <li>{@code extensions} via {@link ProblemDetail#setProperty(String, Object)}
   * </ul>
   *
   * @param p the domain problem payload (must not be {@code null})
   * @return a new {@link ProblemDetail} mirroring the supplied payload
   * @throws NullPointerException if {@code p} is {@code null}
   */
  public ProblemDetail toProblemDetail(final ProblemPayload p) {
    Objects.requireNonNull(p, "problem payload");
    ProblemDetail pd =
        ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(p.status()), p.detail());
    pd.setTitle(p.title());
    pd.setType(p.type());
    pd.setInstance(URI.create(p.instance()));
    p.extensions().forEach(pd::setProperty);
    return pd;
  }
}
