package io.veggieshop.platform.domain.version;

import java.util.Optional;

/**
 * ConsistencyStamped
 *
 * Marker interface for domain objects that expose a consistency/ETag-like version.
 * This interface is intentionally minimal and framework-agnostic.
 *
 * Guidelines:
 * - Prefer returning a present {@link EntityVersion} for persisted entities,
 *   and empty for transient/not-yet-persisted ones.
 * - Do not embed HTTP specifics here; ETag formatting belongs in the web layer.
 */
public interface ConsistencyStamped {

    /**
     * @return the entity's version if known, empty otherwise.
     */
    Optional<EntityVersion> version();

    /**
     * Convenience accessor that enforces presence.
     * @throws IllegalStateException if version is absent.
     */
    default EntityVersion requireVersion() {
        return version().orElseThrow(() ->
                new IllegalStateException("EntityVersion is required but not present"));
    }
}
