// AbacResource.java
package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Optional;

/** Resource attributes relevant for ABAC. */
public record AbacResource(
        @NotBlank String tenantId,
        Optional<String> vendorOwnerId,
        @NotNull Sensitivity sensitivity,
        String resourceType // free-form (e.g., product, price, order, secret)
) {
    public AbacResource {
        vendorOwnerId = vendorOwnerId == null ? Optional.empty() : vendorOwnerId;
        sensitivity = sensitivity == null ? Sensitivity.INTERNAL : sensitivity;
    }

    /** Resource sensitivity aligned with PRD. */
    public enum Sensitivity { PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED_PII }
}
