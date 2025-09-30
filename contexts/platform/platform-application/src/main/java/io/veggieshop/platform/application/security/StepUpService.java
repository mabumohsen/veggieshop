package io.veggieshop.platform.application.security;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * StepUpService orchestrates step-up controls required by ABAC:
 *
 * <ul>
 *   <li>Strong MFA challenges (initiate &amp; verify)
 *   <li>Just-in-time (JIT) elevation windows
 *   <li>Two-person approval workflows
 *   <li>Break-glass (emergency) overrides with strict auditing
 * </ul>
 *
 * <p>This service is deterministic and side-effect free aside from calls to its ports. It is
 * virtual-thread friendly and uses blocking calls to provider and repository ports. Actual
 * persistence, messaging, or external calls are delegated to injected ports.
 *
 * <p>Design principles:
 *
 * <ul>
 *   <li><b>Fail-closed</b> on any ambiguity or missing context.
 *   <li><b>Idempotency-by-key</b> for challenge initiation and approval requests.
 *   <li><b>Short-lived</b> elevation windows, audited and revocable.
 *   <li><b>No trust in client tokens</b>: server-side state is authoritative.
 * </ul>
 */
public class StepUpService {

  private static final Logger log = LoggerFactory.getLogger(StepUpService.class);

  private final Clock clock;
  private final MeterRegistry metrics;
  private final MfaProvider mfaProvider;
  private final ElevationStore elevationStore;
  private final ApprovalBroker approvalBroker;
  private final AuditSink audit;

  // Defaults aligned with PRD (can be externalized to @ConfigurationProperties if desired)
  private final int minElevationMinutes; // e.g., 15 minutes
  private final int maxElevationMinutes; // guardrail, e.g., 60 minutes
  private final Duration challengeTtl; // how long an MFA challenge remains valid

  /**
   * Creates a StepUpService with opinionated defaults.
   *
   * @param clock time source
   * @param metrics Micrometer registry
   * @param mfaProvider MFA provider integration
   * @param elevationStore server-side ticket store
   * @param approvalBroker two-person approval broker
   * @param audit audit sink
   */
  public StepUpService(
      Clock clock,
      MeterRegistry metrics,
      MfaProvider mfaProvider,
      ElevationStore elevationStore,
      ApprovalBroker approvalBroker,
      AuditSink audit) {
    this(
        clock,
        metrics,
        mfaProvider,
        elevationStore,
        approvalBroker,
        audit,
        /*minElevationMinutes*/ 15,
        /*maxElevationMinutes*/ 60,
        Duration.ofMinutes(5));
  }

  /**
   * Creates a StepUpService with custom guardrails and challenge TTL.
   *
   * @param clock time source
   * @param metrics Micrometer registry
   * @param mfaProvider MFA provider integration
   * @param elevationStore server-side ticket store
   * @param approvalBroker two-person approval broker
   * @param audit audit sink
   * @param minElevationMinutes minimum elevation window in minutes (clamped to &ge; 1)
   * @param maxElevationMinutes maximum elevation window in minutes (clamped to &ge; min)
   * @param challengeTtl how long an MFA challenge remains valid
   */
  public StepUpService(
      Clock clock,
      MeterRegistry metrics,
      MfaProvider mfaProvider,
      ElevationStore elevationStore,
      ApprovalBroker approvalBroker,
      AuditSink audit,
      int minElevationMinutes,
      int maxElevationMinutes,
      Duration challengeTtl) {
    this.clock = Objects.requireNonNull(clock, "clock");
    this.metrics = Objects.requireNonNull(metrics, "metrics");
    this.mfaProvider = Objects.requireNonNull(mfaProvider, "mfaProvider");
    this.elevationStore = Objects.requireNonNull(elevationStore, "elevationStore");
    this.approvalBroker = Objects.requireNonNull(approvalBroker, "approvalBroker");
    this.audit = Objects.requireNonNull(audit, "audit");
    this.minElevationMinutes = Math.max(1, minElevationMinutes);
    this.maxElevationMinutes = Math.max(this.minElevationMinutes, maxElevationMinutes);
    this.challengeTtl = Objects.requireNonNull(challengeTtl, "challengeTtl");
  }

  // =========================================================================================
  // MFA (Step-up) — initiate & verify
  // =========================================================================================

  /**
   * Initiate a strong MFA challenge for the user. If an active, unexpired challenge with the same
   * idempotencyKey exists, it will be returned (idempotent).
   *
   * @param tenantId tenant identifier
   * @param userId user identifier
   * @param strength desired MFA strength
   * @param reason human-readable reason (audited)
   * @param idempotencyKey optional idempotency key to deduplicate client retries
   * @param attributes optional extra, non-sensitive attributes to persist with the challenge
   * @return challenge snapshot
   */
  public StepUpChallenge initiateMfaChallenge(
      @NotBlank String tenantId,
      @NotBlank String userId,
      @NotNull Strength strength,
      @NotBlank String reason,
      Optional<String> idempotencyKey,
      Map<String, String> attributes) {
    require(tenantId, userId, reason);
    attributes = (attributes == null) ? Map.of() : Map.copyOf(attributes);

    // Idempotent replay detection (store-owned)
    if (idempotencyKey != null && idempotencyKey.isPresent()) {
      Optional<StepUpChallenge> existing =
          mfaProvider.findActiveChallengeByKey(tenantId, userId, idempotencyKey.get());
      if (existing.isPresent()) {
        return existing.get();
      }
    }

    Instant now = clock.instant();
    Instant expiresAt = now.plus(challengeTtl);
    StepUpChallenge challenge =
        new StepUpChallenge(
            UUID.randomUUID().toString(),
            tenantId,
            userId,
            strength,
            reason,
            now,
            expiresAt,
            (idempotencyKey != null) ? idempotencyKey.orElse(null) : null,
            attributes);

    mfaProvider.createChallenge(challenge);
    metrics.counter("security.stepup.challenge.started", "strength", strength.name()).increment();
    audit.emit(
        AuditEvent.of(
            tenantId,
            userId,
            "STEPUP_CHALLENGE_STARTED",
            Map.of(
                "challengeId",
                challenge.challengeId(),
                "strength",
                strength.name(),
                "reason",
                reason)));
    return challenge;
  }

  /**
   * Verify a previously initiated MFA challenge, and grant a short-lived elevation on success.
   * Elevation duration is bounded by service guardrails.
   *
   * @param tenantId tenant identifier
   * @param userId user identifier
   * @param challengeId challenge identifier
   * @param otpOrProof OTP value or WebAuthn proof
   * @param requestedElevationMinutes desired elevation minutes (guardrailed)
   * @return verification result containing a ticket when granted
   */
  public VerificationResult verifyMfaAndElevate(
      @NotBlank String tenantId,
      @NotBlank String userId,
      @NotBlank String challengeId,
      @NotBlank String otpOrProof,
      @Min(1) int requestedElevationMinutes) {
    require(tenantId, userId, challengeId);

    Optional<StepUpChallenge> opt = mfaProvider.findChallengeById(tenantId, userId, challengeId);
    if (opt.isEmpty()) {
      metrics.counter("security.stepup.challenge.unknown").increment();
      return VerificationResult.denied("Unknown challengeId");
    }

    StepUpChallenge challenge = opt.get();
    Instant now = clock.instant();
    if (challenge.expiresAt().isBefore(now)) {
      metrics.counter("security.stepup.challenge.expired").increment();
      return VerificationResult.denied("Challenge expired");
    }

    boolean ok = mfaProvider.verifyChallenge(challenge, otpOrProof);
    if (!ok) {
      metrics.counter("security.stepup.challenge.failed").increment();
      audit.emit(
          AuditEvent.of(
              tenantId, userId, "STEPUP_CHALLENGE_FAILED", Map.of("challengeId", challengeId)));
      return VerificationResult.denied("Invalid proof");
    }

    int minutes =
        Math.max(minElevationMinutes, Math.min(maxElevationMinutes, requestedElevationMinutes));
    Instant until = now.plus(Duration.ofMinutes(minutes));
    StepUpTicket ticket =
        new StepUpTicket(
            "elev_" + UUID.randomUUID(),
            tenantId,
            userId,
            challenge.strength(),
            challenge.reason(),
            now,
            until,
            /*grantedBy*/ "mfa",
            /*attributes*/ challenge.attributes());

    elevationStore.grant(ticket);
    metrics.counter("security.stepup.elevation.granted").increment();
    audit.emit(
        AuditEvent.of(
            tenantId,
            userId,
            "STEPUP_ELEVATION_GRANTED",
            Map.of("ticket", ticket.token(), "minutes", String.valueOf(minutes))));

    // Mark challenge consumed/closed
    mfaProvider.closeChallenge(challengeId);
    return VerificationResult.granted(ticket);
  }

  // =========================================================================================
  // Two-person approval — request & complete
  // =========================================================================================

  /**
   * Create (or return) a two-person approval request. The approver must be different from
   * requester. If an open request exists with the same idempotencyKey, it will be returned.
   *
   * @param tenantId tenant identifier
   * @param requesterUserId requester user id
   * @param action action display name
   * @param reason reason for audit
   * @param requiredApproverUserId optional explicit approver
   * @param idempotencyKey optional idempotency key
   * @param ttl time-to-live for the approval request
   * @return created (or existing) approval request
   */
  public ApprovalRequest requestTwoPersonApproval(
      @NotBlank String tenantId,
      @NotBlank String requesterUserId,
      @NotBlank String action,
      @NotBlank String reason,
      Optional<String> requiredApproverUserId,
      Optional<String> idempotencyKey,
      Duration ttl) {
    require(tenantId, requesterUserId, action);
    ttl = (ttl == null || ttl.isNegative() || ttl.isZero()) ? Duration.ofMinutes(30) : ttl;

    if (requiredApproverUserId != null
        && requiredApproverUserId.isPresent()
        && requesterUserId.equals(requiredApproverUserId.get())) {
      throw new IllegalArgumentException("Approver must differ from requester");
    }

    if (idempotencyKey != null && idempotencyKey.isPresent()) {
      Optional<ApprovalRequest> existing =
          approvalBroker.findOpenByKey(tenantId, requesterUserId, idempotencyKey.get());
      if (existing.isPresent()) {
        return existing.get();
      }
    }

    Instant now = clock.instant();
    ApprovalRequest req =
        new ApprovalRequest(
            "apr_" + UUID.randomUUID(),
            tenantId,
            requesterUserId,
            action,
            reason,
            (requiredApproverUserId != null) ? requiredApproverUserId.orElse(null) : null,
            now,
            now.plus(ttl),
            ApprovalStatus.PENDING,
            (idempotencyKey != null) ? idempotencyKey.orElse(null) : null,
            null, // decidedBy
            null, // decisionComment
            null // decidedAt
            );

    approvalBroker.create(req);
    metrics.counter("security.approval.requested").increment();
    audit.emit(
        AuditEvent.of(
            tenantId,
            requesterUserId,
            "TWO_PERSON_REQUESTED",
            Map.of("approvalId", req.id(), "action", action)));
    return req;
  }

  /**
   * Approver records a decision and the request transitions out of PENDING.
   *
   * @param tenantId tenant identifier
   * @param approvalId approval request id
   * @param approverUserId user id of approver (must differ from requester)
   * @param approve true to approve; false to deny
   * @param comment optional approval/denial comment
   * @return updated approval request
   */
  public ApprovalRequest approveOrDeny(
      @NotBlank String tenantId,
      @NotBlank String approvalId,
      @NotBlank String approverUserId,
      boolean approve,
      String comment) {
    Optional<ApprovalRequest> opt = approvalBroker.findById(tenantId, approvalId);
    if (opt.isEmpty()) {
      throw new NoSuchElementException("Approval not found: " + approvalId);
    }

    ApprovalRequest current = opt.get();
    if (current.expiresAt().isBefore(clock.instant())) {
      approvalBroker.expire(approvalId);
      metrics.counter("security.approval.expired").increment();
      throw new IllegalStateException("Approval expired");
    }
    if (Objects.equals(current.requesterUserId(), approverUserId)) {
      throw new IllegalArgumentException("Requester cannot self-approve");
    }
    if (current.status() != ApprovalStatus.PENDING) {
      // idempotent: already decided
      return current;
    }

    ApprovalStatus newStatus = approve ? ApprovalStatus.APPROVED : ApprovalStatus.DENIED;
    ApprovalRequest updated =
        current.withStatus(newStatus, approverUserId, comment, clock.instant());
    approvalBroker.update(updated);

    metrics.counter("security.approval.decided", "status", newStatus.name()).increment();
    audit.emit(
        AuditEvent.of(
            tenantId,
            approverUserId,
            approve ? "TWO_PERSON_APPROVED" : "TWO_PERSON_DENIED",
            Map.of(
                "approvalId",
                approvalId,
                "requesterUserId",
                current.requesterUserId(),
                "action",
                current.action())));

    return updated;
  }

  // =========================================================================================
  // Elevation management — query & revoke
  // =========================================================================================

  /** Return an active elevation ticket if one exists. */
  public Optional<StepUpTicket> activeElevation(
      @NotBlank String tenantId, @NotBlank String userId) {
    return elevationStore.findActive(tenantId, userId, clock.instant());
  }

  /** Revoke a specific elevation token. */
  public void revoke(
      @NotBlank String tenantId, @NotBlank String token, @NotBlank String revokedBy) {
    elevationStore.revoke(tenantId, token);
    metrics.counter("security.stepup.elevation.revoked").increment();
    audit.emit(
        AuditEvent.of(tenantId, revokedBy, "STEPUP_ELEVATION_REVOKED", Map.of("ticket", token)));
  }

  // =========================================================================================
  // Break-glass (emergency) — short, audited, revocable
  // =========================================================================================

  /**
   * Issue a break-glass elevation with stringent guardrails and mandatory justification. Intended
   * for emergency remediation; must be reviewed post hoc.
   *
   * @param tenantId tenant identifier
   * @param userId user identifier
   * @param minutes requested minutes (guardrailed)
   * @param justification free-form justification (min 20 chars)
   * @return break-glass elevation ticket
   */
  public StepUpTicket breakGlass(
      @NotBlank String tenantId,
      @NotBlank String userId,
      @Min(1) int minutes,
      @NotBlank String justification) {
    if (justification.trim().length() < 20) {
      throw new IllegalArgumentException("Justification must be at least 20 characters");
    }
    int bounded = Math.min(Math.max(minutes, minElevationMinutes), maxElevationMinutes);
    Instant now = clock.instant();
    StepUpTicket ticket =
        new StepUpTicket(
            "bg_" + UUID.randomUUID(),
            tenantId,
            userId,
            Strength.STRONG,
            "break-glass",
            now,
            now.plus(Duration.ofMinutes(bounded)),
            /*grantedBy*/ "break-glass",
            Map.of("justification", justification));

    elevationStore.grant(ticket);
    metrics.counter("security.stepup.breakglass.granted").increment();
    audit.emit(
        AuditEvent.of(
            tenantId,
            userId,
            "BREAK_GLASS_GRANTED",
            Map.of("ticket", ticket.token(), "minutes", String.valueOf(bounded))));
    return ticket;
  }

  // =========================================================================================
  // Helpers
  // =========================================================================================

  private static void require(String... values) {
    for (String v : values) {
      if (v == null || v.isBlank()) {
        throw new IllegalArgumentException("Missing required value");
      }
    }
  }

  // =========================================================================================
  // Ports (SPI) — implemented in infrastructure layer
  // =========================================================================================

  /** MFA provider integration (e.g., TOTP, WebAuthn, SMS/Email OTP via PCI-compliant vendor). */
  public interface MfaProvider {
    void createChallenge(@NotNull StepUpChallenge challenge);

    Optional<StepUpChallenge> findActiveChallengeByKey(
        @NotBlank String tenantId, @NotBlank String userId, @NotBlank String idempotencyKey);

    Optional<StepUpChallenge> findChallengeById(
        @NotBlank String tenantId, @NotBlank String userId, @NotBlank String challengeId);

    boolean verifyChallenge(@NotNull StepUpChallenge challenge, @NotBlank String otpOrProof);

    void closeChallenge(@NotBlank String challengeId);
  }

  /**
   * Server-side store for elevation tickets (e.g., Redis with TTL or Postgres with cron cleanup).
   */
  public interface ElevationStore {
    void grant(@NotNull StepUpTicket ticket);

    Optional<StepUpTicket> findActive(
        @NotBlank String tenantId, @NotBlank String userId, @NotNull Instant now);

    void revoke(@NotBlank String tenantId, @NotBlank String token);
  }

  /** Two-person approval workflow broker (DB-backed + optional notifications). */
  public interface ApprovalBroker {
    void create(@NotNull ApprovalRequest request);

    Optional<ApprovalRequest> findOpenByKey(
        @NotBlank String tenantId,
        @NotBlank String requesterUserId,
        @NotBlank String idempotencyKey);

    Optional<ApprovalRequest> findById(@NotBlank String tenantId, @NotBlank String approvalId);

    void update(@NotNull ApprovalRequest updated);

    void expire(@NotBlank String approvalId);
  }

  /** Security audit sink (e.g., append to AuditRecord outbox). */
  public interface AuditSink {
    void emit(@NotNull AuditEvent event);
  }

  // =========================================================================================
  // DTOs / Records
  // =========================================================================================

  /** Strength grades for step-up MFA. */
  public enum Strength {
    WEAK,
    STRONG
  }

  /** Approval lifecycle states. */
  public enum ApprovalStatus {
    PENDING,
    APPROVED,
    DENIED,
    EXPIRED
  }

  /**
   * MFA challenge snapshot.
   *
   * @param challengeId challenge identifier
   * @param tenantId tenant identifier
   * @param userId user identifier
   * @param strength desired MFA strength
   * @param reason human-readable reason (audited)
   * @param createdAt creation instant
   * @param expiresAt expiry instant
   * @param idempotencyKey optional idempotency key
   * @param attributes optional, non-sensitive attributes
   */
  public record StepUpChallenge(
      String challengeId,
      String tenantId,
      String userId,
      Strength strength,
      String reason,
      Instant createdAt,
      Instant expiresAt,
      String idempotencyKey,
      Map<String, String> attributes) {

    /** Defensive copy of {@code attributes} to avoid representation exposure. */
    public StepUpChallenge {
      attributes = (attributes == null) ? Map.of() : Map.copyOf(attributes);
    }

    /** Returns an unmodifiable copy to avoid exposing internal state. */
    public Map<String, String> attributes() {
      return Map.copyOf(attributes);
    }
  }

  /**
   * Server-side elevation ticket; token is opaque and validated against the store.
   *
   * @param token opaque token
   * @param tenantId tenant identifier
   * @param userId user identifier
   * @param strength MFA strength that led to elevation (or STRONG for break-glass)
   * @param reason human-readable reason
   * @param issuedAt issue instant
   * @param expiresAt expiry instant
   * @param grantedBy issuing mechanism (e.g., "mfa", "break-glass")
   * @param attributes optional attributes (e.g., justification)
   */
  public record StepUpTicket(
      String token,
      String tenantId,
      String userId,
      Strength strength,
      String reason,
      Instant issuedAt,
      Instant expiresAt,
      String grantedBy,
      Map<String, String> attributes) {

    /** Defensive copy of {@code attributes} to avoid representation exposure. */
    public StepUpTicket {
      attributes = (attributes == null) ? Map.of() : Map.copyOf(attributes);
    }

    /** Returns an unmodifiable copy to avoid exposing internal state. */
    public Map<String, String> attributes() {
      return Map.copyOf(attributes);
    }

    /**
     * Whether the ticket is active at {@code now}.
     *
     * @param now instant to test
     * @return true iff {@code issuedAt &le; now < expiresAt}
     */
    public boolean isActive(Instant now) {
      return (now.equals(issuedAt) || now.isAfter(issuedAt)) && now.isBefore(expiresAt);
    }
  }

  /**
   * Approval request aggregate.
   *
   * @param id approval id
   * @param tenantId tenant identifier
   * @param requesterUserId requester user id
   * @param action action display name
   * @param reason reason for audit
   * @param requiredApproverUserId optional explicit approver
   * @param createdAt creation instant
   * @param expiresAt expiry instant
   * @param status lifecycle state
   * @param idempotencyKey optional idempotency key
   * @param decidedBy approver id (nullable until decided)
   * @param decisionComment comment (nullable until decided)
   * @param decidedAt decision instant (nullable until decided)
   */
  public record ApprovalRequest(
      String id,
      String tenantId,
      String requesterUserId,
      String action,
      String reason,
      String requiredApproverUserId,
      Instant createdAt,
      Instant expiresAt,
      ApprovalStatus status,
      String idempotencyKey,
      String decidedBy,
      String decisionComment,
      Instant decidedAt) {

    /**
     * Returns a copy with the given status/decision metadata.
     *
     * @param newStatus new status
     * @param decidedBy approver user id
     * @param comment decision comment
     * @param at decision instant
     * @return updated request
     */
    public ApprovalRequest withStatus(
        ApprovalStatus newStatus, String decidedBy, String comment, Instant at) {
      return new ApprovalRequest(
          id,
          tenantId,
          requesterUserId,
          action,
          reason,
          requiredApproverUserId,
          createdAt,
          expiresAt,
          newStatus,
          idempotencyKey,
          decidedBy,
          comment,
          at);
    }
  }

  /**
   * Verification outcome for MFA.
   *
   * @param granted whether elevation was granted
   * @param message explanatory message
   * @param ticket elevation ticket when granted; otherwise {@code null}
   */
  public record VerificationResult(boolean granted, String message, StepUpTicket ticket) {
    /** Success factory. */
    public static VerificationResult granted(StepUpTicket t) {
      return new VerificationResult(true, "MFA verified; elevation granted", t);
    }

    /** Failure factory. */
    public static VerificationResult denied(String reason) {
      return new VerificationResult(false, reason, null);
    }
  }

  /**
   * Minimal audit event structure.
   *
   * @param tenantId tenant identifier
   * @param actorUserId actor user id
   * @param type event type
   * @param data event attributes (defensively copied)
   * @param at event timestamp
   */
  public record AuditEvent(
      String tenantId, String actorUserId, String type, Map<String, String> data, Instant at) {

    /** Defensive copy of {@code data} to avoid representation exposure. */
    public AuditEvent {
      data = (data == null) ? Map.of() : Map.copyOf(data);
    }

    /** Returns an unmodifiable copy to avoid exposing internal state. */
    public Map<String, String> data() {
      return Map.copyOf(data);
    }

    /**
     * Convenience factory that stamps {@code at} with {@link Instant#now()}.
     *
     * @param tenantId tenant identifier
     * @param actorUserId actor user id
     * @param type event type
     * @param data event attributes
     * @return new audit event
     */
    public static AuditEvent of(
        String tenantId, String actorUserId, String type, Map<String, String> data) {
      return new AuditEvent(
          tenantId, actorUserId, type, (data == null) ? Map.of() : Map.copyOf(data), Instant.now());
    }
  }
}
