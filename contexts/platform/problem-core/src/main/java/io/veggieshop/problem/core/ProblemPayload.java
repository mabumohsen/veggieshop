package io.veggieshop.problem.core;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable RFC 7807 problem-details payload, framework-agnostic.
 *
 * <p>Defaults and invariants:
 *
 * <ul>
 *   <li>{@code type}: falls back to {@code about:blank} if {@code null}.
 *   <li>{@code title}: falls back to a minimal reason phrase derived from {@code status}.
 *   <li>{@code detail}: falls back to {@code "Request could not be processed."} if blank.
 *   <li>{@code instance}: falls back to {@code "/"} if blank.
 *   <li>{@code extensions}: defensively copied into an unmodifiable {@link Map}.
 * </ul>
 *
 * <p>All fields are intentionally non-PII.
 */
public final class ProblemPayload {
  private final URI type; // e.g. ProblemTypes.ProblemType.uri() or about:blank
  private final String title; // human-readable summary
  private final int status; // HTTP status code (int, no Spring)
  private final String detail; // safe, non-PII detail
  private final String instance; // path or logical instance
  private final Map<String, Object> extensions; // stable, non-PII context + errors

  /**
   * Creates a new {@code ProblemPayload}.
   *
   * @param type absolute or relative type URI (may be {@code null} -> {@code about:blank})
   * @param title short, human-readable summary (blank -> derived from {@code status})
   * @param status HTTP status code
   * @param detail human-readable explanation (blank -> generic fallback)
   * @param instance URI-reference identifying the occurrence (blank -> {@code "/"})
   * @param extensions extra, non-PII key/value pairs; copied defensively (may be {@code null})
   */
  public ProblemPayload(
      URI type,
      String title,
      int status,
      String detail,
      String instance,
      Map<String, Object> extensions) {
    this.type = (type == null ? URI.create("about:blank") : type);
    this.title = (title == null || title.isBlank()) ? defaultTitle(status) : title;
    this.status = status;
    this.detail = (detail == null || detail.isBlank()) ? "Request could not be processed." : detail;
    this.instance = (instance == null || instance.isBlank()) ? "/" : instance;
    this.extensions =
        Collections.unmodifiableMap(
            new LinkedHashMap<>(extensions == null ? Map.of() : extensions));
  }

  /** Returns the problem {@code type} URI (never {@code null}). */
  public URI type() {
    return type;
  }

  /** Returns the short, human-readable title (never blank). */
  public String title() {
    return title;
  }

  /** Returns the HTTP status code. */
  public int status() {
    return status;
  }

  /** Returns the human-readable detail message (never blank). */
  public String detail() {
    return detail;
  }

  /** Returns the instance URI-reference (never blank). */
  public String instance() {
    return instance;
  }

  /** Returns an unmodifiable map of additional, non-PII extensions. */
  public Map<String, Object> extensions() {
    return extensions;
  }

  // Minimal reason-phrases without Spring dependency
  private static String defaultTitle(int status) {
    return switch (status) {
      case 400 -> "Bad Request";
      case 401 -> "Unauthorized";
      case 403 -> "Forbidden";
      case 404 -> "Not Found";
      case 405 -> "Method Not Allowed";
      case 409 -> "Conflict";
      case 415 -> "Unsupported Media Type";
      case 422 -> "Unprocessable Entity";
      case 429 -> "Too Many Requests";
      case 500 -> "Internal Server Error";
      case 503 -> "Service Unavailable";
      default -> "Error";
    };
  }
}
