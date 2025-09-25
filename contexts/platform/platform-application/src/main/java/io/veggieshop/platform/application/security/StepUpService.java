package io.veggieshop.platform.application.security;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * StepUpService orchestrates step-up controls required by ABAC:
 * <ul>
 *   <li>Strong MFA challenges (initiate & verify)</li>
 *   <li>Just-in-time (JIT) elevation windows</li>
 *   <li>Two-person approval workflows</li>
 *   <li>Break-glass (emergency) overrides with strict auditing</li>
 * </ul>
 *
 * <p>This service is deterministic and side-effect free aside from calls to its ports.
 * It is virtual-thread friendly and uses blocking calls to provider and repository ports.
 * Actual persistence, messaging, or external calls are delegated to injected ports.</p>
 *
 * <p>Design principles:
 * <ul>
 *   <li><b>Fail-closed</b> on any ambiguity or missing context.</li>
 *   <li><b>Idempotency-by-key</b> for challenge initiation and approval requests.</li>
 *   <li><b>Short-lived</b> elevation windows, audited and revocable.</li>
 *   <li><b>No trust in client tokens</b>: server-side state is authoritative.</li>
 * </ul>
 * </p>
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
    private final Duration challengeTtl;   // how long an MFA challenge remains valid

    public StepUpService(
            Clock clock,
            MeterRegistry metrics,
            MfaProvider mfaProvider,
            ElevationStore elevationStore,
            ApprovalBroker approvalBroker,
            AuditSink audit
    ) {
        this(clock, metrics, mfaProvider, elevationStore, approvalBroker, audit,
                /*minElevationMinutes*/ 15, /*maxElevationMinutes*/ 60, Duration.ofMinutes(5));
    }

    public StepUpService(
            Clock clock,
            MeterRegistry metrics,
            MfaProvider mfaProvider,
            ElevationStore elevationStore,
            ApprovalBroker approvalBroker,
            AuditSink audit,
            int minElevationMinutes,
            int maxElevationMinutes,
            Duration challengeTtl
    ) {
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
     * Initiate a strong MFA challenge for the user. If an active, unexpired challenge with the
     * same idempotencyKey exists, it will be returned (idempotent).
     */
    public StepUpChallenge initiateMfaChallenge(
            @NotBlank String tenantId,
            @NotBlank String userId,
            @NotNull Strength strength,
            @NotBlank String reason,
            Optional<String> idempotencyKey,
            Map<String, String> attributes
    ) {
        require(tenantId, userId, reason);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);

        // Idempotent replay detection (store-owned)
        if (idempotencyKey != null && idempotencyKey.isPresent()) {
            Optional<StepUpChallenge> existing = mfaProvider.findActiveChallengeByKey(tenantId, userId, idempotencyKey.get());
            if (existing.isPresent()) {
                return existing.get();
            }
        }

        Instant now = clock.instant();
        Instant expiresAt = now.plus(challengeTtl);
        StepUpChallenge challenge = new StepUpChallenge(
                UUID.randomUUID().toString(),
                tenantId,
                userId,
                strength,
                reason,
                now,
                expiresAt,
                idempotencyKey != null ? idempotencyKey.orElse(null) : null,
                attributes
        );

        mfaProvider.createChallenge(challenge);
        metrics.counter("security.stepup.challenge.started", "strength", strength.name()).increment();
        audit.emit(AuditEvent.of(tenantId, userId, "STEPUP_CHALLENGE_STARTED",
                Map.of("challengeId", challenge.challengeId(), "strength", strength.name(), "reason", reason)));
        return challenge;
    }

    /**
     * Verify a previously initiated MFA challenge, and grant a short-lived elevation on success.
     * Elevation duration is bounded by service guardrails.
     */
    public VerificationResult verifyMfaAndElevate(
            @NotBlank String tenantId,
            @NotBlank String userId,
            @NotBlank String challengeId,
            @NotBlank String otpOrProof,
            @Min(1) int requestedElevationMinutes
    ) {
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
            audit.emit(AuditEvent.of(tenantId, userId, "STEPUP_CHALLENGE_FAILED",
                    Map.of("challengeId", challengeId)));
            return VerificationResult.denied("Invalid proof");
        }

        int minutes = Math.max(minElevationMinutes, Math.min(maxElevationMinutes, requestedElevationMinutes));
        Instant until = now.plus(Duration.ofMinutes(minutes));
        StepUpTicket ticket = new StepUpTicket(
                "elev_" + UUID.randomUUID(),
                tenantId, userId,
                challenge.strength(),
                challenge.reason(),
                now, until,
                /*grantedBy*/ "mfa",
                /*attributes*/ challenge.attributes()
        );

        elevationStore.grant(ticket);
        metrics.counter("security.stepup.elevation.granted").increment();
        audit.emit(AuditEvent.of(tenantId, userId, "STEPUP_ELEVATION_GRANTED",
                Map.of("ticket", ticket.token(), "minutes", String.valueOf(minutes))));

        // Mark challenge consumed/closed
        mfaProvider.closeChallenge(challengeId);
        return VerificationResult.granted(ticket);
    }

    // =========================================================================================
    // Two-person approval — request & complete
    // =========================================================================================

    /**
     * Create (or return) a two-person approval request. The approver must be different from requester.
     * If an open request exists with the same idempotencyKey, it will be returned.
     */
    public ApprovalRequest requestTwoPersonApproval(
            @NotBlank String tenantId,
            @NotBlank String requesterUserId,
            @NotBlank String action,
            @NotBlank String reason,
            Optional<String> requiredApproverUserId,
            Optional<String> idempotencyKey,
            Duration ttl
    ) {
        require(tenantId, requesterUserId, action);
        ttl = (ttl == null || ttl.isNegative() || ttl.isZero()) ? Duration.ofMinutes(30) : ttl;

        if (requiredApproverUserId != null && requiredApproverUserId.isPresent()
                && requesterUserId.equals(requiredApproverUserId.get())) {
            throw new IllegalArgumentException("Approver must differ from requester");
        }

        if (idempotencyKey != null && idempotencyKey.isPresent()) {
            Optional<ApprovalRequest> existing = approvalBroker.findOpenByKey(tenantId, requesterUserId, idempotencyKey.get());
            if (existing.isPresent()) return existing.get();
        }

        Instant now = clock.instant();
        ApprovalRequest req = new ApprovalRequest(
                "apr_" + UUID.randomUUID(),
                tenantId,
                requesterUserId,
                action,
                reason,
                requiredApproverUserId != null ? requiredApproverUserId.orElse(null) : null,
                now,
                now.plus(ttl),
                ApprovalStatus.PENDING,
                idempotencyKey != null ? idempotencyKey.orElse(null) : null,
                null,   // decidedBy
                null,   // decisionComment
                null    // decidedAt
        );

        approvalBroker.create(req);
        metrics.counter("security.approval.requested").increment();
        audit.emit(AuditEvent.of(tenantId, requesterUserId, "TWO_PERSON_REQUESTED",
                Map.of("approvalId", req.id(), "action", action)));
        return req;
    }

    /**
     * Approver records a decision. Returns the updated approval request.
     */
    public ApprovalRequest approveOrDeny(
            @NotBlank String tenantId,
            @NotBlank String approvalId,
            @NotBlank String approverUserId,
            boolean approve,
            String comment
    ) {
        Optional<ApprovalRequest> opt = approvalBroker.findById(tenantId, approvalId);
        if (opt.isEmpty()) throw new NoSuchElementException("Approval not found: " + approvalId);

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
            return current; // idempotent: already decided
        }

        ApprovalStatus newStatus = approve ? ApprovalStatus.APPROVED : ApprovalStatus.DENIED;
        ApprovalRequest updated = current.withStatus(newStatus, approverUserId, comment, clock.instant());
        approvalBroker.update(updated);

        metrics.counter("security.approval.decided", "status", newStatus.name()).increment();
        audit.emit(AuditEvent.of(tenantId, approverUserId,
                approve ? "TWO_PERSON_APPROVED" : "TWO_PERSON_DENIED",
                Map.of("approvalId", approvalId, "requesterUserId", current.requesterUserId(), "action", current.action())));

        return updated;
    }

    // =========================================================================================
    // Elevation management — query & revoke
    // =========================================================================================

    /** Return an active elevation ticket if one exists. */
    public Optional<StepUpTicket> activeElevation(@NotBlank String tenantId, @NotBlank String userId) {
        return elevationStore.findActive(tenantId, userId, clock.instant());
    }

    /** Revoke a specific elevation token. */
    public void revoke(@NotBlank String tenantId, @NotBlank String token, @NotBlank String revokedBy) {
        elevationStore.revoke(tenantId, token);
        metrics.counter("security.stepup.elevation.revoked").increment();
        audit.emit(AuditEvent.of(tenantId, revokedBy, "STEPUP_ELEVATION_REVOKED", Map.of("ticket", token)));
    }

    // =========================================================================================
    // Break-glass (emergency) — short, audited, revocable
    // =========================================================================================

    /**
     * Issue a break-glass elevation with stringent guardrails and mandatory justification.
     * Intended for emergency remediation; must be reviewed post hoc.
     */
    public StepUpTicket breakGlass(
            @NotBlank String tenantId,
            @NotBlank String userId,
            @Min(1) int minutes,
            @NotBlank String justification
    ) {
        if (justification.trim().length() < 20) {
            throw new IllegalArgumentException("Justification must be at least 20 characters");
        }
        int bounded = Math.min(Math.max(minutes, minElevationMinutes), maxElevationMinutes);
        Instant now = clock.instant();
        StepUpTicket ticket = new StepUpTicket(
                "bg_" + UUID.randomUUID(),
                tenantId, userId,
                Strength.STRONG,
                "break-glass",
                now, now.plus(Duration.ofMinutes(bounded)),
                /*grantedBy*/ "break-glass",
                Map.of("justification", justification)
        );

        elevationStore.grant(ticket);
        metrics.counter("security.stepup.breakglass.granted").increment();
        audit.emit(AuditEvent.of(tenantId, userId, "BREAK_GLASS_GRANTED",
                Map.of("ticket", ticket.token(), "minutes", String.valueOf(bounded))));
        return ticket;
    }

    // =========================================================================================
    // Helpers
    // =========================================================================================

    private static void require(String... values) {
        for (String v : values) {
            if (v == null || v.isBlank()) throw new IllegalArgumentException("Missing required value");
        }
    }

    // =========================================================================================
    // Ports (SPI) — implemented in infrastructure layer
    // =========================================================================================

    /** MFA provider integration (e.g., TOTP, WebAuthn, SMS/Email OTP via PCI-compliant vendor). */
    public interface MfaProvider {
        void createChallenge(@NotNull StepUpChallenge challenge);
        Optional<StepUpChallenge> findActiveChallengeByKey(@NotBlank String tenantId, @NotBlank String userId, @NotBlank String idempotencyKey);
        Optional<StepUpChallenge> findChallengeById(@NotBlank String tenantId, @NotBlank String userId, @NotBlank String challengeId);
        boolean verifyChallenge(@NotNull StepUpChallenge challenge, @NotBlank String otpOrProof);
        void closeChallenge(@NotBlank String challengeId);
    }

    /** Server-side store for elevation tickets (e.g., Redis with TTL or Postgres with cron cleanup). */
    public interface ElevationStore {
        void grant(@NotNull StepUpTicket ticket);
        Optional<StepUpTicket> findActive(@NotBlank String tenantId, @NotBlank String userId, @NotNull Instant now);
        void revoke(@NotBlank String tenantId, @NotBlank String token);
    }

    /** Two-person approval workflow broker (DB-backed + optional notifications). */
    public interface ApprovalBroker {
        void create(@NotNull ApprovalRequest request);
        Optional<ApprovalRequest> findOpenByKey(@NotBlank String tenantId, @NotBlank String requesterUserId, @NotBlank String idempotencyKey);
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
    public enum Strength { WEAK, STRONG }

    /** Approval lifecycle states. */
    public enum ApprovalStatus { PENDING, APPROVED, DENIED, EXPIRED }

    /** MFA challenge snapshot. */
    public record StepUpChallenge(
            String challengeId,
            String tenantId,
            String userId,
            Strength strength,
            String reason,
            Instant createdAt,
            Instant expiresAt,
            String idempotencyKey,
            Map<String, String> attributes
    ) {}

    /** Server-side elevation ticket; token is opaque and validated against the store. */
    public record StepUpTicket(
            String token,
            String tenantId,
            String userId,
            Strength strength,
            String reason,
            Instant issuedAt,
            Instant expiresAt,
            String grantedBy,
            Map<String, String> attributes
    ) {
        public boolean isActive(Instant now) {
            return (now.equals(issuedAt) || now.isAfter(issuedAt)) && now.isBefore(expiresAt);
        }
    }

    /** Approval request aggregate. */
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
            // Decision fields (nullable until decided)
            String decidedBy,
            String decisionComment,
            Instant decidedAt
    ) {
        public ApprovalRequest withStatus(ApprovalStatus newStatus, String decidedBy, String comment, Instant at) {
            return new ApprovalRequest(id, tenantId, requesterUserId, action, reason, requiredApproverUserId,
                    createdAt, expiresAt, newStatus, idempotencyKey, decidedBy, comment, at);
        }
    }

    /** Verification outcome for MFA. */
    public record VerificationResult(boolean granted, String message, StepUpTicket ticket) {
        public static VerificationResult granted(StepUpTicket t) {
            return new VerificationResult(true, "MFA verified; elevation granted", t);
        }
        public static VerificationResult denied(String reason) {
            return new VerificationResult(false, reason, null);
        }
    }

    /** Minimal audit event structure. */
    public record AuditEvent(String tenantId, String actorUserId, String type, Map<String, String> data, Instant at) {
        public static AuditEvent of(String tenantId, String actorUserId, String type, Map<String, String> data) {
            return new AuditEvent(tenantId, actorUserId, type, data == null ? Map.of() : Map.copyOf(data), Instant.now());
        }
    }
}
