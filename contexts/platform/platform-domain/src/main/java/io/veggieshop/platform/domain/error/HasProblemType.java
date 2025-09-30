package io.veggieshop.platform.domain.error;

import io.veggieshop.platform.domain.error.ProblemTypes.ProblemType;

/**
 * Marker interface for exceptions or error carriers that expose a {@link ProblemType} describing
 * the RFC7807 problem semantics.
 */
public interface HasProblemType {
  /**
   * Returns the {@link ProblemType} associated with this error.
   *
   * @return the problem type (never {@code null})
   */
  ProblemType type();
}
