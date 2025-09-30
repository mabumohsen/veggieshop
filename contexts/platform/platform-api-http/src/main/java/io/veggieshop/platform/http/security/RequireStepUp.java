package io.veggieshop.platform.http.security;

import io.veggieshop.platform.domain.security.RiskLevel;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller class or handler method as requiring “step-up” (stronger) authentication.
 *
 * <p>When present, downstream security middleware should verify that the authenticated principal
 * has recently satisfied the configured multi-factor authentication (MFA) or equivalent
 * authentication method reference (AMR) at or above the desired {@link RiskLevel}.
 *
 * <p>May be placed on a type or a method. Method-level settings override type-level settings.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Inherited
@Documented
public @interface RequireStepUp {

  /**
   * The required risk level for step-up authentication.
   *
   * @return the desired {@link RiskLevel}; defaults to {@link RiskLevel#HIGH}
   */
  RiskLevel value() default RiskLevel.HIGH;

  /**
   * Maximum acceptable age of the MFA/AMR event, in seconds.
   *
   * <p>Use {@code -1} to defer to system defaults from configuration.
   *
   * @return the max age in seconds, or {@code -1} to use defaults
   */
  long maxAgeSeconds() default -1;

  /**
   * Short-circuit allow if the principal has <em>any</em> of these roles.
   *
   * @return an array of role names; empty means no role shortcut
   */
  String[] anyRole() default {};

  /**
   * Short-circuit allow if the principal has <em>any</em> of these scopes.
   *
   * @return an array of scope names; empty means no scope shortcut
   */
  String[] anyScope() default {};
}
