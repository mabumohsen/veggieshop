package io.veggieshop.problem.core;

public record FieldViolation(String field, String message, String code) {
    public static FieldViolation of(String field, String message, String code) {
        return new FieldViolation(
                field == null ? "" : field,
                message == null || message.isBlank() ? "Invalid value" : message,
                (code == null || code.isBlank()) ? null : code
        );
    }
}
