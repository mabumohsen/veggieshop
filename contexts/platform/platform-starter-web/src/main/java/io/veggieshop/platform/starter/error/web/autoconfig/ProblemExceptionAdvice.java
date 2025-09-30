package io.veggieshop.platform.starter.error.web.autoconfig;

import io.veggieshop.platform.domain.error.ProblemTypes;
import io.veggieshop.platform.domain.error.VeggieException;
import io.veggieshop.platform.http.error.ProblemHttpMapper;
import io.veggieshop.problem.core.FieldViolation;
import io.veggieshop.problem.core.ProblemFactory;
import io.veggieshop.problem.core.ProblemPayload;
import io.veggieshop.problem.core.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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

/**
 * Centralized RFC7807 mapping for web endpoints.
 *
 * <p>Notes:
 *
 * <ul>
 *   <li>Depends only on problem-core + domain error types.
 *   <li>Decoupled from api-http via {@link RequestContextProvider} and local {@link
 *       ProblemHttpMapper}.
 *   <li>Registered by auto-configuration.
 * </ul>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class ProblemExceptionAdvice {

  private static final MediaType PROBLEM_JSON = MediaType.APPLICATION_PROBLEM_JSON;

  private final ProblemFactory factory;
  private final ProblemHttpMapper mapper;
  private final RequestContextProvider ctxProvider;

  /**
   * Creates the advice with the required collaborators.
   *
   * @param factory problem factory used to build RFC7807 payloads
   * @param mapper maps {@link io.veggieshop.problem.core.ProblemPayload} to {@link
   *     org.springframework.http.ProblemDetail}
   * @param ctxProvider extracts request-scoped context (method, path, ids) from the HTTP request
   */
  public ProblemExceptionAdvice(
      ProblemFactory factory, ProblemHttpMapper mapper, RequestContextProvider ctxProvider) {
    this.factory = factory;
    this.mapper = mapper;
    this.ctxProvider = ctxProvider;
  }

  // -------------------------- Domain --------------------------

  /** Maps {@link VeggieException} to Problem+JSON with the declared status and type. */
  @ExceptionHandler(VeggieException.class)
  public ResponseEntity<ProblemDetail> handleVeggie(HttpServletRequest req, VeggieException ex) {
    RequestContext ctx = ctxProvider.from(req);
    int status = ex.status();
    ProblemPayload p = factory.build(ctx, status, ex.type(), ex.getMessage(), null, null);
    return respond(p, status, null);
  }

  // -------------------------- Validation --------------------------

  /** Maps Spring binding errors to a 400 with field violations. */
  @ExceptionHandler(BindException.class)
  public ResponseEntity<ProblemDetail> handleBind(HttpServletRequest req, BindException ex) {
    RequestContext ctx = ctxProvider.from(req);
    List<FieldViolation> errs = new ArrayList<>(ex.getErrorCount());
    ex.getBindingResult()
        .getAllErrors()
        .forEach(
            err -> {
              if (err instanceof FieldError fe) {
                errs.add(
                    FieldViolation.of(fe.getField(), safe(err.getDefaultMessage()), fe.getCode()));
              } else {
                errs.add(
                    FieldViolation.of(
                        err.getObjectName(), safe(err.getDefaultMessage()), err.getCode()));
              }
            });
    ProblemPayload p =
        factory.badRequestWithErrors(
            ctx, ProblemTypes.VALIDATION_FAILED, errs, "Validation failed for request.");
    return respond(p, 400, null);
  }

  /** Maps argument type mismatches to 400 with a friendly detail. */
  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ProblemDetail> handleTypeMismatch(
      HttpServletRequest req, MethodArgumentTypeMismatchException ex) {
    RequestContext ctx = ctxProvider.from(req);
    String field = ex.getName(); // Non-null by contract
    Class<?> type = ex.getRequiredType();
    String required = (type != null ? type.getSimpleName() : "type");
    List<FieldViolation> errs = List.of(FieldViolation.of(field, "Invalid value", "TYPE_MISMATCH"));
    ProblemPayload p =
        factory.badRequestWithErrors(
            ctx,
            ProblemTypes.VALIDATION_FAILED,
            errs,
            "Expected " + required + " for '" + field + "'.");
    return respond(p, 400, null);
  }

  /** Maps missing request parameter to 400 with field violations. */
  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<ProblemDetail> handleMissingParam(
      HttpServletRequest req, MissingServletRequestParameterException ex) {
    RequestContext ctx = ctxProvider.from(req);
    List<FieldViolation> errs =
        List.of(
            FieldViolation.of(ex.getParameterName(), "Required parameter is missing", "MISSING"));
    ProblemPayload p =
        factory.badRequestWithErrors(
            ctx,
            ProblemTypes.VALIDATION_FAILED,
            errs,
            "Missing required parameter '" + ex.getParameterName() + "'.");
    return respond(p, 400, null);
  }

  /** Maps missing header to 400 with field violations. */
  @ExceptionHandler(MissingRequestHeaderException.class)
  public ResponseEntity<ProblemDetail> handleMissingHeader(
      HttpServletRequest req, MissingRequestHeaderException ex) {
    RequestContext ctx = ctxProvider.from(req);
    List<FieldViolation> errs =
        List.of(FieldViolation.of(ex.getHeaderName(), "Required header is missing", "MISSING"));
    ProblemPayload p =
        factory.badRequestWithErrors(
            ctx,
            ProblemTypes.VALIDATION_FAILED,
            errs,
            "Missing required header '" + ex.getHeaderName() + "'.");
    return respond(p, 400, null);
  }

  /** Maps malformed JSON/body to a 400 validation problem. */
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ProblemDetail> handleMalformed(
      HttpServletRequest req, HttpMessageNotReadableException ex) {
    RequestContext ctx = ctxProvider.from(req);
    ProblemPayload p =
        factory.build(
            ctx,
            400,
            ProblemTypes.VALIDATION_FAILED,
            "Malformed request body.",
            "MALFORMED_BODY",
            null);
    return respond(p, 400, null);
  }

  // -------------------------- Protocol --------------------------

  /** Maps unsupported media type to 415. */
  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  public ResponseEntity<ProblemDetail> handleUnsupported(
      HttpServletRequest req, HttpMediaTypeNotSupportedException ex) {
    RequestContext ctx = ctxProvider.from(req);
    ProblemPayload p =
        factory.build(
            ctx,
            415,
            ProblemTypes.UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type.",
            "UNSUPPORTED_MEDIA_TYPE",
            null);

    HttpHeaders headers = new HttpHeaders();
    if (!ex.getSupportedMediaTypes().isEmpty()) {
      headers.setAccept(ex.getSupportedMediaTypes());
    }
    return respond(p, 415, headers);
  }

  /** Maps method not allowed to 405 and sets Allow if available. */
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ProblemDetail> handleMethodNotAllowed(
      HttpServletRequest req, HttpRequestMethodNotSupportedException ex) {
    RequestContext ctx = ctxProvider.from(req);
    ProblemPayload p =
        factory.build(
            ctx,
            405,
            null,
            "HTTP method not allowed for this endpoint.",
            "METHOD_NOT_ALLOWED",
            null);

    HttpHeaders headers = new HttpHeaders();
    Set<HttpMethod> supported = ex.getSupportedHttpMethods();
    if (supported != null && !supported.isEmpty()) {
      headers.setAllow(supported);
    }
    return respond(p, 405, headers);
  }

  // -------------------------- Explicit status exceptions --------------------------

  /** Maps {@link ResponseStatusException} to Problem+JSON using its status and reason. */
  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ProblemDetail> handleResponseStatus(
      HttpServletRequest req, ResponseStatusException ex) {
    RequestContext ctx = ctxProvider.from(req);
    int status = ex.getStatusCode().value();
    String detail = safe(ex.getReason());
    ProblemPayload p = factory.build(ctx, status, null, detail, null, null);
    return respond(p, status, null);
  }

  /** Maps {@link ErrorResponseException} to Problem+JSON using its {@link ProblemDetail}. */
  @ExceptionHandler(ErrorResponseException.class)
  public ResponseEntity<ProblemDetail> handleErrorResponse(
      HttpServletRequest req, ErrorResponseException ex) {
    RequestContext ctx = ctxProvider.from(req);
    int status = ex.getStatusCode().value();
    // getBody() is non-null by contract
    String detail = safe(ex.getBody().getDetail());
    ProblemPayload p = factory.build(ctx, status, null, detail, null, null);
    return respond(p, status, null);
  }

  // -------------------------- Fallback --------------------------

  /** Final safety net: hides internals and returns a 500 problem. */
  @ExceptionHandler(Throwable.class)
  public ResponseEntity<ProblemDetail> handleOther(HttpServletRequest req, Throwable ex) {
    RequestContext ctx = ctxProvider.from(req);
    ProblemPayload p = factory.internalServerError(ctx);
    return respond(p, 500, null);
  }

  // -------------------------- helpers --------------------------

  /**
   * Converts a {@link ProblemPayload} to a {@link ProblemDetail} response with the correct content
   * type and optional headers.
   */
  private ResponseEntity<ProblemDetail> respond(
      @NonNull ProblemPayload p, int status, HttpHeaders headersOrNull) {
    HttpHeaders headers = (headersOrNull == null ? new HttpHeaders() : headersOrNull);
    headers.setContentType(PROBLEM_JSON);
    return new ResponseEntity<>(mapper.toProblemDetail(p), headers, HttpStatus.valueOf(status));
  }

  private static String safe(Object o) {
    String s = (o == null ? null : String.valueOf(o));
    return (s == null || s.isBlank()) ? "Request could not be processed." : s;
  }
}
