package io.veggieshop.platform.starter.error;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.http.error.ProblemHttpMapper;
import io.veggieshop.problem.core.FieldViolation;
import io.veggieshop.problem.core.ProblemFactory;
import io.veggieshop.problem.core.ProblemPayload;
import io.veggieshop.problem.core.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.lang.NonNull;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

/**
 * Centralized RFC7807 mapping for web endpoints.
 *
 * <p>
 * Notes:
 * <ul>
 *   <li>Depends only on problem-core + domain error types.</li>
 *   <li>Decoupled from api-http by using {@link RequestContextProvider} and a local {@link ProblemHttpMapper} bean.</li>
 *   <li>Registered via starter-web auto-configuration (ProblemWebAutoConfiguration).</li>
 * </ul>
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class ProblemExceptionAdvice {

    private static final MediaType PROBLEM_JSON = MediaType.APPLICATION_PROBLEM_JSON;

    private final ProblemFactory factory;
    private final ProblemHttpMapper mapper;
    private final RequestContextProvider ctxProvider;

    public ProblemExceptionAdvice(ProblemFactory factory,
                                  ProblemHttpMapper mapper,
                                  RequestContextProvider ctxProvider) {
        this.factory = factory;
        this.mapper = mapper;
        this.ctxProvider = ctxProvider;
    }

    // -------------------------- Domain --------------------------

    @ExceptionHandler(VeggieException.class)
    public ResponseEntity<ProblemDetail> handleVeggie(HttpServletRequest req, VeggieException ex) {
        RequestContext ctx = ctxProvider.from(req);
        int status = ex.status();
        ProblemPayload p = factory.build(ctx, status, ex.type(), ex.getMessage(), null, null);
        return respond(p, status, null);
    }

    // -------------------------- Validation --------------------------

    @ExceptionHandler(BindException.class)
    public ResponseEntity<ProblemDetail> handleBind(HttpServletRequest req, BindException ex) {
        RequestContext ctx = ctxProvider.from(req);
        List<FieldViolation> errs = new ArrayList<>(ex.getErrorCount());
        ex.getBindingResult().getAllErrors().forEach(err -> {
            if (err instanceof FieldError fe) {
                errs.add(FieldViolation.of(fe.getField(), safe(err.getDefaultMessage()), fe.getCode()));
            } else {
                errs.add(FieldViolation.of(err.getObjectName(), safe(err.getDefaultMessage()), err.getCode()));
            }
        });
        ProblemPayload p = factory.badRequestWithErrors(ctx, ProblemTypes.VALIDATION_FAILED, errs,
                "Validation failed for request.");
        return respond(p, 400, null);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ProblemDetail> handleTypeMismatch(HttpServletRequest req, MethodArgumentTypeMismatchException ex) {
        RequestContext ctx = ctxProvider.from(req);
        String field = (ex.getName() != null ? ex.getName() : "parameter");
        String required = (ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "type");
        List<FieldViolation> errs = List.of(FieldViolation.of(field, "Invalid value", "TYPE_MISMATCH"));
        ProblemPayload p = factory.badRequestWithErrors(ctx, ProblemTypes.VALIDATION_FAILED, errs,
                "Expected " + required + " for '" + field + "'.");
        return respond(p, 400, null);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ProblemDetail> handleMissingParam(HttpServletRequest req, MissingServletRequestParameterException ex) {
        RequestContext ctx = ctxProvider.from(req);
        List<FieldViolation> errs = List.of(FieldViolation.of(ex.getParameterName(), "Required parameter is missing", "MISSING"));
        ProblemPayload p = factory.badRequestWithErrors(ctx, ProblemTypes.VALIDATION_FAILED, errs,
                "Missing required parameter '" + ex.getParameterName() + "'.");
        return respond(p, 400, null);
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ProblemDetail> handleMissingHeader(HttpServletRequest req, MissingRequestHeaderException ex) {
        RequestContext ctx = ctxProvider.from(req);
        List<FieldViolation> errs = List.of(FieldViolation.of(ex.getHeaderName(), "Required header is missing", "MISSING"));
        ProblemPayload p = factory.badRequestWithErrors(ctx, ProblemTypes.VALIDATION_FAILED, errs,
                "Missing required header '" + ex.getHeaderName() + "'.");
        return respond(p, 400, null);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ProblemDetail> handleMalformed(HttpServletRequest req, HttpMessageNotReadableException ex) {
        RequestContext ctx = ctxProvider.from(req);
        ProblemPayload p = factory.build(ctx, 400, ProblemTypes.VALIDATION_FAILED,
                "Malformed request body.", "MALFORMED_BODY", null);
        return respond(p, 400, null);
    }

    // -------------------------- Protocol --------------------------

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleUnsupported(HttpServletRequest req, HttpMediaTypeNotSupportedException ex) {
        RequestContext ctx = ctxProvider.from(req);
        ProblemPayload p = factory.build(ctx, 415, ProblemTypes.UNSUPPORTED_MEDIA_TYPE,
                "Unsupported media type.", "UNSUPPORTED_MEDIA_TYPE", null);

        HttpHeaders headers = new HttpHeaders();
        if (!ex.getSupportedMediaTypes().isEmpty()) headers.setAccept(ex.getSupportedMediaTypes());
        return respond(p, 415, headers);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleMethodNotAllowed(HttpServletRequest req, HttpRequestMethodNotSupportedException ex) {
        RequestContext ctx = ctxProvider.from(req);
        ProblemPayload p = factory.build(ctx, 405, null,
                "HTTP method not allowed for this endpoint.", "METHOD_NOT_ALLOWED", null);

        HttpHeaders headers = new HttpHeaders();
        if (ex.getSupportedHttpMethods() != null && !ex.getSupportedHttpMethods().isEmpty()) {
            headers.setAllow(ex.getSupportedHttpMethods());
        }
        return respond(p, 405, headers);
    }

    // -------------------------- Explicit status exceptions --------------------------

    @ExceptionHandler({ ResponseStatusException.class, ErrorResponseException.class })
    public ResponseEntity<ProblemDetail> handleStatusExceptions(HttpServletRequest req, Exception ex) {
        RequestContext ctx = ctxProvider.from(req);
        int status;
        String detail;
        if (ex instanceof ResponseStatusException rse) {
            status = rse.getStatusCode().value();
            detail = safe(rse.getReason());
        } else {
            var ere = (ErrorResponseException) ex;
            status = ere.getStatusCode().value();
            detail = (ere.getBody() != null ? safe(ere.getBody().getDetail()) : null);
        }
        ProblemPayload p = factory.build(ctx, status, null, detail, null, null);
        return respond(p, status, null);
    }

    // -------------------------- Fallback --------------------------

    @ExceptionHandler(Throwable.class)
    public ResponseEntity<ProblemDetail> handleOther(HttpServletRequest req, Throwable ex) {
        RequestContext ctx = ctxProvider.from(req);
        ProblemPayload p = factory.internalServerError(ctx);
        return respond(p, 500, null);
    }

    // -------------------------- helpers --------------------------

    private ResponseEntity<ProblemDetail> respond(@NonNull ProblemPayload p, int status, HttpHeaders headersOrNull) {
        HttpHeaders headers = (headersOrNull == null ? new HttpHeaders() : headersOrNull);
        headers.setContentType(PROBLEM_JSON);
        return new ResponseEntity<>(mapper.toProblemDetail(p), headers, HttpStatus.valueOf(status));
    }

    private static String safe(Object o) {
        String s = (o == null ? null : String.valueOf(o));
        return (s == null || s.isBlank()) ? "Request could not be processed." : s;
    }
}
