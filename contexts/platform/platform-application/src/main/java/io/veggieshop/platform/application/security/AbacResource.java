/*
 * VeggieShop Platform - ABAC types
 */

package io.veggieshop.platform.application.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Optional;

/**
 * Resource attributes relevant for ABAC.
 *
 * @param tenantId resource tenant identifier
 * @param vendorOwnerId optional vendor owner id (for multi-vendor scoping)
 * @param sensitivity resource sensitivity classification
 * @param resourceType free-form logical type (e.g., product, price, order, secret)
 */
public record AbacResource(
    @NotBlank String tenantId,
    Optional<String> vendorOwnerId,
    @NotNull Sensitivity sensitivity,
    String resourceType) {
  /** Canonicalizes nulls and defaults sensitivity to {@link Sensitivity#INTERNAL}. */
  public AbacResource {
    vendorOwnerId = (vendorOwnerId == null) ? Optional.empty() : vendorOwnerId;
    sensitivity = (sensitivity == null) ? Sensitivity.INTERNAL : sensitivity;
  }

  /** Resource sensitivity aligned with PRD. */
  public enum Sensitivity {
    PUBLIC,
    INTERNAL,
    CONFIDENTIAL,
    RESTRICTED_PII
  }
}
