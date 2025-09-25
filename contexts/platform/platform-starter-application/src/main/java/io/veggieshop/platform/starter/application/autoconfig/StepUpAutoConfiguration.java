package io.veggieshop.platform.starter.application.autoconfig;

import io.micrometer.core.instrument.MeterRegistry;
import io.veggieshop.platform.application.security.StepUpService;
import io.veggieshop.platform.application.security.StepUpService.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@AutoConfiguration
@EnableConfigurationProperties(VeggieStepUpProperties.class)
public class StepUpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock stepUpClock() { return Clock.systemUTC(); }

    @Bean
    @ConditionalOnMissingBean(StepUpService.class)
    StepUpService stepUpService(Clock clock,
                                MeterRegistry metrics,
                                MfaProvider mfaProvider,
                                ElevationStore elevationStore,
                                ApprovalBroker approvalBroker,
                                AuditSink auditSink,
                                VeggieStepUpProperties p) {
        return new StepUpService(
                clock, metrics, mfaProvider, elevationStore, approvalBroker, auditSink,
                p.getMinElevationMinutes(),
                p.getMaxElevationMinutes(),
                p.getChallengeTtl()
        );
    }

    // ====================== ديفولتات Dev/Local (اختيارية) ======================
    // تُنشأ فقط إذا ما فيه Beans توفرت من التطبيق.

    @Bean
    @ConditionalOnMissingBean(MfaProvider.class)
    @ConditionalOnProperty(prefix="veggieshop.stepup.dev", name="mfa-provider", havingValue="in-memory", matchIfMissing = true)
    MfaProvider inMemoryMfaProvider() {
        return new InMemoryMfaProvider();
    }

    @Bean
    @ConditionalOnMissingBean(ElevationStore.class)
    @ConditionalOnProperty(prefix="veggieshop.stepup.dev", name="elevation-store", havingValue="in-memory", matchIfMissing = true)
    ElevationStore inMemoryElevationStore() {
        return new InMemoryElevationStore();
    }

    @Bean
    @ConditionalOnMissingBean(ApprovalBroker.class)
    @ConditionalOnProperty(prefix="veggieshop.stepup.dev", name="approval-broker", havingValue="in-memory", matchIfMissing = true)
    ApprovalBroker inMemoryApprovalBroker() {
        return new InMemoryApprovalBroker();
    }

    @Bean
    @ConditionalOnMissingBean(AuditSink.class)
    AuditSink loggingAuditSink() {
        return event -> {
            // تجنب أي بيانات حساسة—هنا في ستارتر فقط للـdev
            System.out.println("[AUDIT] type=" + event.type() + " tenant=" + event.tenantId() + " actor=" + event.actorUserId());
        };
    }

    // ======= Implementations محلية بسيطة لأغراض التطوير =======

    static final class InMemoryMfaProvider implements MfaProvider {
        private final Map<String, StepUpChallenge> byId = new ConcurrentHashMap<>();
        private final Map<String, StepUpChallenge> byKey = new ConcurrentHashMap<>();

        @Override
        public void createChallenge(StepUpChallenge c) {
            byId.put(c.challengeId(), c);
            if (c.idempotencyKey() != null) {
                byKey.put(key(c.tenantId(), c.userId(), c.idempotencyKey()), c);
            }
        }
        @Override
        public Optional<StepUpChallenge> findActiveChallengeByKey(String tenantId, String userId, String idempotencyKey) {
            StepUpChallenge c = byKey.get(key(tenantId,userId,idempotencyKey));
            if (c == null) return Optional.empty();
            return c.expiresAt().isAfter(Instant.now()) ? Optional.of(c) : Optional.empty();
        }
        @Override
        public Optional<StepUpChallenge> findChallengeById(String tenantId, String userId, String challengeId) {
            StepUpChallenge c = byId.get(challengeId);
            if (c == null) return Optional.empty();
            if (!tenantId.equals(c.tenantId()) || !userId.equals(c.userId())) return Optional.empty();
            return Optional.of(c);
        }
        @Override
        public boolean verifyChallenge(StepUpChallenge challenge, String otpOrProof) {
            // للتجارب: اعتبر أي قيمة طولها >=6 صحيحة
            return otpOrProof != null && otpOrProof.length() >= 6;
        }
        @Override
        public void closeChallenge(String challengeId) { byId.remove(challengeId); }
        private static String key(String t, String u, String k) { return t+"|"+u+"|"+k; }
    }

    static final class InMemoryElevationStore implements ElevationStore {
        private final Map<String, StepUpTicket> tickets = new ConcurrentHashMap<>();
        @Override
        public void grant(StepUpTicket t) { tickets.put(t.token(), t); }
        @Override
        public Optional<StepUpTicket> findActive(String tenantId, String userId, Instant now) {
            return tickets.values().stream()
                    .filter(t -> t.tenantId().equals(tenantId) && t.userId().equals(userId) && t.isActive(now))
                    .findFirst();
        }
        @Override
        public void revoke(String tenantId, String token) { tickets.remove(token); }
    }

    static final class InMemoryApprovalBroker implements ApprovalBroker {
        private final Map<String, ApprovalRequest> store = new ConcurrentHashMap<>();
        private final Map<String, String> openByKey = new ConcurrentHashMap<>(); // key -> id

        @Override
        public void create(ApprovalRequest r) {
            store.put(r.id(), r);
            if (r.idempotencyKey() != null) {
                openByKey.put(key(r.tenantId(), r.requesterUserId(), r.idempotencyKey()), r.id());
            }
        }
        @Override
        public Optional<ApprovalRequest> findOpenByKey(String tenantId, String requesterUserId, String idempotencyKey) {
            String id = openByKey.get(key(tenantId, requesterUserId, idempotencyKey));
            if (id == null) return Optional.empty();
            ApprovalRequest r = store.get(id);
            return (r != null && r.status() == ApprovalStatus.PENDING) ? Optional.of(r) : Optional.empty();
        }
        @Override
        public Optional<ApprovalRequest> findById(String tenantId, String approvalId) {
            ApprovalRequest r = store.get(approvalId);
            return (r != null && r.tenantId().equals(tenantId)) ? Optional.of(r) : Optional.empty();
        }
        @Override
        public void update(ApprovalRequest updated) { store.put(updated.id(), updated); }
        @Override
        public void expire(String approvalId) {
            store.computeIfPresent(approvalId, (id, cur) ->
                    cur.withStatus(ApprovalStatus.EXPIRED, cur.decidedBy(), cur.decisionComment(), Instant.now())
            );
        }
        private static String key(String t, String u, String k) { return t+"|"+u+"|"+k; }
    }
}
