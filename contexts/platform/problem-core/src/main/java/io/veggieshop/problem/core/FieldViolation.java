package io.veggieshop.problem.core;

/**
 * Represents a single field-level validation error to be embedded in problem responses.
 *
 * @param field the logical field name (never {@code null}; empty if unknown)
 * @param message human-readable message (never {@code null}; defaults to "Invalid value")
 * @param code optional machine-friendly error code; may be {@code null}
 */
public record FieldViolation(String field, String message, String code) {

  /**
   * Factory method that normalizes null/blank inputs.
   *
   * @param field the field name; if {@code null} becomes empty
   * @param message the error message; if {@code null} or blank becomes "Invalid value"
   * @param code optional error code; blank treated as {@code null}
   * @return a normalized {@link FieldViolation}
   */
  public static FieldViolation of(String field, String message, String code) {
    return new FieldViolation(
        field == null ? "" : field,
        (message == null || message.isBlank()) ? "Invalid value" : message,
        (code == null || code.isBlank()) ? null : code);
  }
}
