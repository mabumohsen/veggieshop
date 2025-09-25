package io.veggieshop.problem.core;

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
        long timestamp
) {}
