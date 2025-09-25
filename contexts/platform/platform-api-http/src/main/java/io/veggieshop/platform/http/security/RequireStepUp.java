package io.veggieshop.platform.http.security;

import io.veggieshop.platform.domain.security.RiskLevel;

import java.lang.annotation.*;

/**
 * Declares that the annotated controller class or handler method
 * requires "step-up" (stronger) authentication.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Documented
public @interface RequireStepUp {
    RiskLevel value() default RiskLevel.HIGH;
    /** Max acceptable age (seconds) of the MFA/AMR event; -1 means use default from settings. */
    long maxAgeSeconds() default -1;
    /** Short-circuit allow if the principal has ANY of these roles. */
    String[] anyRole() default {};
    /** Short-circuit allow if the principal has ANY of these scopes. */
    String[] anyScope() default {};
}
