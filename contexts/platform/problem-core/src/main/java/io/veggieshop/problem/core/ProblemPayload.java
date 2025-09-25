package io.veggieshop.problem.core;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ProblemPayload {
    private final URI type;         // e.g. ProblemTypes.ProblemType.uri() or about:blank
    private final String title;     // human-readable summary
    private final int status;       // HTTP status code (int, no Spring)
    private final String detail;    // safe, non-PII detail
    private final String instance;  // path or logical instance
    private final Map<String, Object> extensions; // stable, non-PII context + errors

    public ProblemPayload(URI type, String title, int status, String detail, String instance, Map<String, Object> extensions) {
        this.type = (type == null ? URI.create("about:blank") : type);
        this.title = (title == null || title.isBlank()) ? defaultTitle(status) : title;
        this.status = status;
        this.detail = (detail == null || detail.isBlank()) ? "Request could not be processed." : detail;
        this.instance = (instance == null || instance.isBlank()) ? "/" : instance;
        this.extensions = Collections.unmodifiableMap(new LinkedHashMap<>(extensions == null ? Map.of() : extensions));
    }

    public URI type() { return type; }
    public String title() { return title; }
    public int status() { return status; }
    public String detail() { return detail; }
    public String instance() { return instance; }
    public Map<String, Object> extensions() { return extensions; }

    private static String defaultTitle(int status) {
        // Minimal reason-phrases without Spring dependency
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
