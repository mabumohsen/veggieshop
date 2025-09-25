package io.veggieshop.problem.core;

import io.veggieshop.platform.domain.error.ProblemTypes.ProblemType;

import java.net.URI;
import java.util.*;

public final class ProblemFactory {

    public ProblemPayload build(
            RequestContext ctx,
            int status,
            ProblemType type,
            String detail,
            String problemCode,
            List<FieldViolation> errors
    ) {
        Map<String, Object> ext = baseExtensions(ctx);

        // problemCode: explicit > derived from type.slug() > absent
        String code = (problemCode != null && !problemCode.isBlank())
                ? problemCode
                : (type != null ? safe(type.slug()) : null);
        if (code != null) ext.put("problemCode", code);

        // structured errors (as list of maps to keep RFC7807 "extensions" simple/flat)
        if (errors != null && !errors.isEmpty()) {
            List<Map<String, Object>> list = new ArrayList<>(errors.size());
            for (FieldViolation fv : errors) {
                Map<String, Object> m = new LinkedHashMap<>(3);
                m.put("field", safe(fv.field()));
                m.put("message", safe(fv.message()));
                if (fv.code() != null && !fv.code().isBlank()) m.put("code", fv.code());
                list.add(m);
            }
            ext.put("errors", list);
        }

        URI typeUri = (type != null && type.uri() != null) ? type.uri() : URI.create("about:blank");
        String title = (type != null && safe(type.title()) != null) ? type.title() : null;

        return new ProblemPayload(
                typeUri,
                title,
                status,
                detail,
                safe(ctx == null ? null : ctx.path()),
                ext
        );
    }

    public ProblemPayload badRequestWithErrors(RequestContext ctx, ProblemType type, List<FieldViolation> errors, String detail) {
        return build(ctx, 400, type, detail, null, errors);
    }

    public ProblemPayload internalServerError(RequestContext ctx) {
        return build(ctx, 500, null, "An unexpected error occurred.", null, null);
    }

    public ProblemPayload tooManyRequests(RequestContext ctx, String detail) {
        return build(ctx, 429, null, detail, "RATE_LIMITED", null);
    }

    // ---------------- helpers ----------------
    private static Map<String, Object> baseExtensions(RequestContext ctx) {
        Map<String, Object> m = new LinkedHashMap<>(12);
        if (ctx == null) return m;
        put(m, "traceId", ctx.traceId());
        put(m, "spanId", ctx.spanId());
        put(m, "requestId", ctx.requestId());
        put(m, "correlationId", ctx.correlationId());
        put(m, "tenantId", ctx.tenantId());
        if (ctx.timestamp() > 0) m.put("timestamp", ctx.timestamp());
        put(m, "method", ctx.method());
        put(m, "path", ctx.path());
        if (ctx.headerCount() >= 0) m.put("headerCount", ctx.headerCount());
        if (ctx.paramCount() >= 0) m.put("paramCount", ctx.paramCount());
        return m;
    }

    private static void put(Map<String, Object> m, String k, String v) {
        if (v != null && !v.isBlank()) m.put(k, v);
    }

    private static String safe(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
