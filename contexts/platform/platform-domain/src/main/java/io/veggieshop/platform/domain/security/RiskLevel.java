package io.veggieshop.platform.domain.security;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * RiskLevel
 *
 * <p>Enterprise-grade risk taxonomy used across authorization, step-up MFA, and operational
 * controls. The scale is intentionally small, ordered, and stable to keep policies and audits
 * predictable.
 *
 * <h2>Levels (ascending severity)</h2>
 *
 * <ul>
 *   <li><b>LOW</b> – Routine operations on non-sensitive resources.
 *   <li><b>MEDIUM</b> – Important actions or internal data; extra scrutiny.
 *   <li><b>HIGH</b> – Sensitive operations or data classes (PII/PHI); step-up MFA is typically
 *       required.
 *   <li><b>CRITICAL</b> – Highly sensitive or dangerous actions (pricing overrides, refunds, admin
 *       changes); two-person approval and strict controls are expected.
 * </ul>
 *
 * <h2>Design notes</h2>
 *
 * <ul>
 *   <li>Implements common helpers (escalate/deescalate, max, fromScore) for consistent policy
 *       decisions.
 *   <li>Provides {@link #recommendedControls()} as a sane default aligned with the PRD
 *       (MFA/2-person approval).
 *   <li>No framework dependencies; safe for use in domain and application layers.
 * </ul>
 */
public enum RiskLevel {
  LOW(10, "Routine, low-impact operations"),
  MEDIUM(40, "Moderate impact; internal or controlled data"),
  HIGH(70, "Sensitive operations/data; strong auth required"),
  CRITICAL(90, "High-risk admin/financial actions; strict controls");

  private final int severityScore; // 0..100 for coarse scoring/alarm thresholds
  private final String description;

  RiskLevel(int severityScore, String description) {
    this.severityScore = severityScore;
    this.description = description;
  }

  /** Coarse-grained numeric severity in the range ~[0..100]. */
  public int severityScore() {
    return severityScore;
  }

  /** Human-friendly description for audits and dashboards. */
  public String description() {
    return description;
  }

  // -------------------------
  // Comparisons & arithmetic
  // -------------------------

  /** Returns whether this level is greater than or equal to the other level. */
  public boolean isAtLeast(RiskLevel other) {
    return this.ordinal() >= other.ordinal();
  }

  /** Returns whether this level is strictly higher than the other level. */
  public boolean isHigherThan(RiskLevel other) {
    return this.ordinal() > other.ordinal();
  }

  /** Escalate by one step, clamped at {@link #CRITICAL}. */
  public RiskLevel escalate() {
    return escalate(1);
  }

  /** Escalate by {@code steps}, clamped to {@link #CRITICAL}. */
  public RiskLevel escalate(int steps) {
    int idx = Math.min(CRITICAL.ordinal(), this.ordinal() + Math.max(0, steps));
    return RiskLevel.values()[idx];
  }

  /** Deescalate by one step, clamped at {@link #LOW}. */
  public RiskLevel deescalate() {
    return deescalate(1);
  }

  /** Deescalate by {@code steps}, clamped to {@link #LOW}. */
  public RiskLevel deescalate(int steps) {
    int idx = Math.max(LOW.ordinal(), this.ordinal() - Math.max(0, steps));
    return RiskLevel.values()[idx];
  }

  /** Clamp this level to the inclusive range {@code [min, max]}. */
  public RiskLevel clamp(RiskLevel min, RiskLevel max) {
    Objects.requireNonNull(min, "min");
    Objects.requireNonNull(max, "max");
    if (min.ordinal() > max.ordinal()) {
      throw new IllegalArgumentException("min must be <= max");
    }
    if (this.ordinal() < min.ordinal()) {
      return min;
    }
    if (this.ordinal() > max.ordinal()) {
      return max;
    }
    return this;
  }

  // -------------------------
  // Aggregation helpers
  // -------------------------

  /** Max of two risk levels (by severity). */
  public static RiskLevel max(RiskLevel a, RiskLevel b) {
    Objects.requireNonNull(a, "a");
    Objects.requireNonNull(b, "b");
    return a.ordinal() >= b.ordinal() ? a : b;
  }

  /** Max of many risk levels (by severity). Returns LOW if none provided. */
  public static RiskLevel max(RiskLevel... levels) {
    if (levels == null || levels.length == 0) {
      return LOW;
    }
    RiskLevel out = LOW;
    for (RiskLevel rl : levels) {
      if (rl != null && rl.ordinal() > out.ordinal()) {
        out = rl;
      }
    }
    return out;
  }

  // -------------------------
  // Mapping & parsing
  // -------------------------

  /**
   * Map a coarse score (0..100) to a {@link RiskLevel}.
   *
   * <ul>
   *   <li>0–24 → LOW
   *   <li>25–49 → MEDIUM
   *   <li>50–74 → HIGH
   *   <li>75–100 → CRITICAL
   * </ul>
   */
  public static RiskLevel fromScore(int score0to100) {
    int s = Math.max(0, Math.min(100, score0to100));
    if (s >= 75) {
      return CRITICAL;
    }
    if (s >= 50) {
      return HIGH;
    }
    if (s >= 25) {
      return MEDIUM;
    }
    return LOW;
  }

  /** Lenient, case-insensitive parse. Returns {@code defaultLevel} if input is null/blank. */
  public static RiskLevel parseOrDefault(String value, RiskLevel defaultLevel) {
    if (value == null || value.isBlank()) {
      return defaultLevel == null ? LOW : defaultLevel;
    }
    String v = value.trim().toUpperCase(Locale.ROOT);
    try {
      return RiskLevel.valueOf(v);
    } catch (IllegalArgumentException ex) {
      return defaultLevel == null ? LOW : defaultLevel;
    }
  }

  // -------------------------
  // Control recommendations
  // -------------------------

  /**
   * Recommended controls for the given level. These are defaults aligned with the PRD; policy
   * engines can add stricter gates.
   */
  public Set<Control> recommendedControls() {
    return switch (this) {
      case LOW -> EnumSet.of(Control.BASELINE_AUDIT);
      case MEDIUM -> EnumSet.of(Control.BASELINE_AUDIT, Control.ENHANCED_AUDIT);
      case HIGH ->
          EnumSet.of(
              Control.BASELINE_AUDIT,
              Control.ENHANCED_AUDIT,
              Control.STEP_UP_MFA,
              Control.JUST_IN_TIME_ELEVATION,
              Control.RATE_LIMIT_TIGHT);
      case CRITICAL ->
          EnumSet.of(
              Control.BASELINE_AUDIT,
              Control.ENHANCED_AUDIT,
              Control.STEP_UP_MFA,
              Control.JUST_IN_TIME_ELEVATION,
              Control.TWO_PERSON_APPROVAL,
              Control.RATE_LIMIT_TIGHT,
              Control.MANUAL_CHANGE_WINDOW);
    };
  }

  /**
   * Control hints consumed by higher layers (policy engine, interceptors, UI). These are
   * <b>signals</b>, not automatic behaviors in the domain layer.
   */
  public enum Control {
    /** Always log with correlation/trace, retain per audit policy. */
    BASELINE_AUDIT,
    /** Structured security/audit event with extra fields and higher retention. */
    ENHANCED_AUDIT,
    /** Require step-up MFA (e.g., 3DS2/strong OTP/HW key) prior to action. */
    STEP_UP_MFA,
    /** Just-in-time elevation for the specific action with tight TTL and scoping. */
    JUST_IN_TIME_ELEVATION,
    /** Two distinct approvers required before proceeding. */
    TWO_PERSON_APPROVAL,
    /** Apply tighter rate limits and anomaly detection for the action. */
    RATE_LIMIT_TIGHT,
    /** Restrict execution to change windows or require explicit break-glass. */
    MANUAL_CHANGE_WINDOW
  }
}
