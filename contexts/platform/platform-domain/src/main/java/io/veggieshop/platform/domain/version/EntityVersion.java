package io.veggieshop.platform.domain.version;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import java.util.Optional;

/**
 * EntityVersion
 *
 * A small, immutable value object that represents a monotonic entity version.
 * Designed to be framework-agnostic and safe across storage/transport layers.
 *
 * Invariants:
 * - value >= 0 (0 can be used to mean "unversioned"/"not yet persisted" if your domain needs that)
 * - strictly increasing across updates (enforced by callers using {@link #next()})
 *
 * Notes:
 * - This type intentionally avoids HTTP concerns (ETag formatting/parsing).
 *   Keep HTTP-specific logic in the web layer.
 */
public final class EntityVersion implements Comparable<EntityVersion>, Serializable {

    @Serial private static final long serialVersionUID = 1L;

    /** A conventional 'unversioned' constant (opt-in; treat as you see fit). */
    public static final EntityVersion UNVERSIONED = new EntityVersion(0L);

    /** A convenient starting point if you prefer 1-based versions. */
    public static final EntityVersion INITIAL = new EntityVersion(1L);

    private final long value;

    private EntityVersion(long value) {
        if (value < 0L) {
            throw new IllegalArgumentException("EntityVersion must be >= 0, got: " + value);
        }
        this.value = value;
    }

    /**
     * Factory with validation.
     */
    public static EntityVersion of(long value) {
        return value == 0L ? UNVERSIONED : new EntityVersion(value);
    }

    /**
     * Tries to parse a decimal string into an {@link EntityVersion}.
     * Returns empty on null/blank/invalid format or negative numbers.
     */
    public static Optional<EntityVersion> tryParse(String raw) {
        if (raw == null) return Optional.empty();
        String s = raw.trim();
        if (s.isEmpty()) return Optional.empty();
        try {
            long v = Long.parseLong(s);
            return (v >= 0L) ? Optional.of(of(v)) : Optional.empty();
        } catch (NumberFormatException ex) {
            return Optional.empty();
        }
    }

    /**
     * @return the underlying numeric value (non-negative).
     */
    public long value() {
        return value;
    }

    /**
     * @return whether this instance represents an "unversioned" state (value == 0).
     */
    public boolean isUnversioned() {
        return value == 0L;
    }

    /**
     * @return a new instance with value+1 (overflow-safe).
     * @throws ArithmeticException if increment would overflow {@link Long#MAX_VALUE}
     */
    public EntityVersion next() {
        if (value == Long.MAX_VALUE) {
            throw new ArithmeticException("EntityVersion overflow: cannot increment Long.MAX_VALUE");
        }
        long next = value + 1L;
        return of(next);
    }

    /** Convenience helpers */
    public boolean isAfter(EntityVersion other) {
        Objects.requireNonNull(other, "other");
        return this.value > other.value;
    }

    public boolean isBefore(EntityVersion other) {
        Objects.requireNonNull(other, "other");
        return this.value < other.value;
    }

    public static EntityVersion max(EntityVersion a, EntityVersion b) {
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
        return (a.value >= b.value) ? a : b;
    }

    public static EntityVersion min(EntityVersion a, EntityVersion b) {
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
        return (a.value <= b.value) ? a : b;
    }

    @Override
    public int compareTo(EntityVersion o) {
        return Long.compare(this.value, o.value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        return (o instanceof EntityVersion that) && this.value == that.value;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(value);
    }

    /**
     * Keep toString minimal and safe for logs (no PII).
     */
    @Override
    public String toString() {
        return Long.toString(value);
    }
}
