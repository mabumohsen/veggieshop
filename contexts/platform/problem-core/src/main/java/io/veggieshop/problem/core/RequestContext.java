package io.veggieshop.problem.core;

/**
 * Minimal, immutable request metadata used to enrich {@link ProblemPayload#extensions()}.
 *
 * @param method HTTP method, e.g. {@code GET}
 * @param path request path (no query string)
 * @param tenantId resolved tenant identifier (if any)
 * @param traceId distributed trace id
 * @param spanId distributed span id
 * @param requestId application-level request id
 * @param correlationId external/system correlation id
 * @param headerCount number of request headers
 * @param paramCount number of request parameters
 * @param timestamp request timestamp in epoch milliseconds
 */
public record RequestContext(
    String method,
    String path,
    String tenantId,
    String traceId,
    String spanId,
    String requestId,
    String correlationId,
    int headerCount,
    int paramCount,
    long timestamp) {}
