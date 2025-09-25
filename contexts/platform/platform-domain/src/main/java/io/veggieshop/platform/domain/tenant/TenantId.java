package io.veggieshop.platform.domain.tenant;

import java.io.Serial;
import java.io.Serializable;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Enterprise-grade immutable tenant identifier.
 * - Lowercase ASCII letters, digits and single hyphens, 3..63 chars.
 * - No leading/trailing hyphen and no consecutive "--".
 * - Framework-agnostic (pure domain).
 */
public record TenantId(String value) implements Comparable<TenantId>, Serializable {

    @Serial private static final long serialVersionUID = 1L;

    public static final int MIN_LENGTH = 3;
    public static final int MAX_LENGTH = 63;

    private static final Pattern ALLOWED = Pattern.compile("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$");

    public TenantId {
        Objects.requireNonNull(value, "tenantId must not be null");
        String normalized = normalize(value);
        if (!isValid(normalized)) {
            throw new IllegalArgumentException(
                    "Invalid tenantId: '%s' (must match %s, length %d..%d, no \"--\")"
                            .formatted(value, ALLOWED.pattern(), MIN_LENGTH, MAX_LENGTH));
        }
        value = normalized;
    }

    public static TenantId of(String raw) {
        return new TenantId(raw);
    }

    public static Optional<TenantId> tryParse(String raw) {
        if (raw == null) return Optional.empty();
        String n = normalize(raw);
        return isValid(n) ? Optional.of(new TenantId(n)) : Optional.empty();
    }

    public static boolean isValid(String candidate) {
        if (candidate == null) return false;
        int len = candidate.length();
        if (len < MIN_LENGTH || len > MAX_LENGTH) return false;
        if (!ALLOWED.matcher(candidate).matches()) return false;
        if (candidate.contains("--")) return false;
        return true;
    }

    public String obfuscated() {
        int len = value.length();
        if (len <= 5) return "***";
        return value.substring(0, 3) + "…" + value.substring(len - 2);
    }

    private static String normalize(String raw) {
        return raw.trim().toLowerCase(Locale.ROOT);
    }

    @Override
    public int compareTo(TenantId other) {
        return this.value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
