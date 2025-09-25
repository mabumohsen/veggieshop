package io.veggieshop.platform.application.consistency;

import io.veggieshop.platform.application.consistency.token.ConsistencyToken;
import io.veggieshop.platform.application.consistency.token.TokenSigner;

import java.io.Serial;
import java.io.Serializable;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * ConsistencyService
 *
 * Framework-agnostic core that:
 *  - Tracks a per-tenant "watermark" of the last observed write.
 *  - Parses/verifies client-sent consistency tokens and enforces tenant consistency.
 *  - Emits new tokens for responses binding the (tenant, watermark).
 *  - Maintains per-request state via a ThreadLocal Scope.
 *
 * WatermarkStore is pluggable; a default in-memory implementation is provided for tests/dev.
 */
public final class ConsistencyService {

    // ----------------- SPI: Watermark store -----------------

    /** Abstraction for the per-tenant watermark (monotonic timestamp, epoch millis). */
    public interface WatermarkStore {
        /** @return current watermark for tenant (0 if none). */
        long current(String tenant);
        /** Advance to at least the provided value; @return updated watermark. */
        long advanceAtLeast(String tenant, long epochMillis);
        /** Advance to now(); convenience using service clock. */
        long advanceToNow(String tenant);
    }

    /** Simple single-node store. Replace with Redis/Kafka etc. in production. */
    public static final class InMemoryWatermarkStore implements WatermarkStore, Serializable {
        @Serial private static final long serialVersionUID = 1L;
        private final Clock clock;
        private final Map<String, AtomicLong> map = new ConcurrentHashMap<>();
        public InMemoryWatermarkStore(Clock clock) { this.clock = Objects.requireNonNull(clock); }
        @Override public long current(String tenant) { return map.computeIfAbsent(tenant, t -> new AtomicLong()).get(); }
        @Override public long advanceAtLeast(String tenant, long epochMillis) {
            AtomicLong l = map.computeIfAbsent(tenant, t -> new AtomicLong());
            l.accumulateAndGet(epochMillis, Math::max);
            return l.get();
        }
        @Override public long advanceToNow(String tenant) {
            return advanceAtLeast(tenant, clock.millis());
        }
        @Override public String toString() { return "InMemoryWatermarkStore{size=" + map.size() + "}"; }
    }

    // ----------------- Request state -----------------

    /** Thread-local request scope state. */
    public static final class RequestState {
        private final String tenant;
        private final Optional<ConsistencyToken> ifConsistentWith;
        private final Optional<ConsistencyToken> priorToken;
        private final long startedAtMillis;

        RequestState(String tenant,
                     Optional<ConsistencyToken> ifConsistentWith,
                     Optional<ConsistencyToken> priorToken,
                     long startedAtMillis) {
            this.tenant = tenant;
            this.ifConsistentWith = ifConsistentWith;
            this.priorToken = priorToken;
            this.startedAtMillis = startedAtMillis;
        }

        public String tenant() { return tenant; }
        public Optional<ConsistencyToken> ifConsistentWith() { return ifConsistentWith; }
        public Optional<ConsistencyToken> priorToken() { return priorToken; }
        public long startedAtMillis() { return startedAtMillis; }

        /** Watermark the client wants us to read at/after. */
        public long requiredWatermarkOrZero() {
            return ifConsistentWith.map(ConsistencyToken::watermarkMillis).orElse(0L);
        }
    }

    /** Scope that restores prior request state on close. */
    public final class Scope implements AutoCloseable {
        private final RequestState previous;
        private Scope(RequestState prev) { this.previous = prev; }
        @Override public void close() { TL.set(previous); }
    }

    // ----------------- Fields -----------------

    private final TokenSigner signer;
    private final ConsistencyProperties props;
    private final Clock clock;
    private final WatermarkStore store;

    /** Per-thread request state. */
    private static final ThreadLocal<RequestState> TL = new ThreadLocal<>();

    // ----------------- Construction -----------------

    public ConsistencyService(TokenSigner signer,
                              ConsistencyProperties props,
                              Clock clock,
                              WatermarkStore store) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.props  = Objects.requireNonNull(props, "props");
        this.clock  = Objects.requireNonNull(clock, "clock");
        this.store  = Objects.requireNonNull(store, "store");
    }

    /** Convenient factory using in-memory store (tests/dev). */
    public static ConsistencyService withInMemoryStore(TokenSigner signer,
                                                       ConsistencyProperties props,
                                                       Clock clock) {
        return new ConsistencyService(signer, props, clock, new InMemoryWatermarkStore(clock));
    }

    // ----------------- Request lifecycle -----------------

    /**
     * Open a request scope:
     *  - parse/verify If-Consistent-With & prior token (X-Consistency-Token)
     *  - enforce tenant match if present
     *  - seed watermark from prior token to reduce waits
     */
    public Scope openRequest(String tenant,
                             String ifConsistentWithCompact,
                             String priorTokenCompact) {
        Objects.requireNonNull(tenant, "tenant");
        final RequestState prev = TL.get();

        Optional<ConsistencyToken> ifcw = parseValidForTenant(ifConsistentWithCompact, tenant);
        Optional<ConsistencyToken> prior = parseValidForTenant(priorTokenCompact, tenant);

        // Seed watermark from prior token if newer
        prior.ifPresent(tok -> store.advanceAtLeast(tenant, tok.watermarkMillis()));

        final RequestState next = new RequestState(tenant, ifcw, prior, clock.millis());
        TL.set(next);
        return new Scope(prev);
    }

    /** @return current request state or empty. */
    public Optional<RequestState> currentRequest() { return Optional.ofNullable(TL.get()); }

    /** @return current tenant or empty. */
    public Optional<String> currentTenant() {
        RequestState s = TL.get();
        return s == null ? Optional.empty() : Optional.of(s.tenant());
    }

    // ----------------- Token operations -----------------

    /** Parse & verify compact token; ensure tenant matches and TTL is respected. */
    public Optional<ConsistencyToken> parseValidForTenant(String compact, String expectedTenant) {
        if (compact == null || compact.isBlank()) return Optional.empty();
        Optional<ConsistencyToken> tok = ConsistencyToken.parseAndVerify(compact, signer);
        if (tok.isEmpty()) return Optional.empty();
        ConsistencyToken t = tok.get();

        // tenant match
        if (!expectedTenant.equals(t.tenant())) {
            // strict: reject cross-tenant tokens
            return Optional.empty();
        }
        // TTL check (accept within TTL + skew)
        long ttlMillis = props.tokenTtl().toMillis() + props.clockSkew().toMillis();
        if (t.isExpired(ttlMillis, clock)) {
            return Optional.empty();
        }
        return Optional.of(t);
    }

    /** Emit a compact token for the given tenant using the store watermark (and optional entity version). */
    public String emitTokenForTenant(String tenant, Long entityVersionOrNull) {
        long wm = store.current(tenant);
        ConsistencyToken token = ConsistencyToken.of(tenant, clock.millis(), wm, entityVersionOrNull);
        return token.encode(signer);
    }

    /** Emit a token for the current request tenant; throws if no scope. */
    public String emitTokenForCurrentTenant(Long entityVersionOrNull) {
        String tenant = currentTenant().orElseThrow(() -> new IllegalStateException("No request scope"));
        return emitTokenForTenant(tenant, entityVersionOrNull);
    }

    // ----------------- Watermark operations -----------------

    /** Advance watermark for tenant to "now" (called after successful write). */
    public long markWriteNow(String tenant) {
        return store.advanceToNow(tenant);
    }

    /** Advance watermark for current request tenant to "now". */
    public long markWriteNow() {
        String tenant = currentTenant().orElseThrow(() -> new IllegalStateException("No request scope"));
        return store.advanceToNow(tenant);
    }

    /** @return current watermark for tenant. */
    public long currentWatermark(String tenant) { return store.current(tenant); }

    /** @return current watermark for current request tenant; 0 if no scope. */
    public long currentWatermarkOrZero() {
        RequestState s = TL.get();
        return (s == null) ? 0L : store.current(s.tenant());
    }

    // ----------------- Accessors -----------------

    public ConsistencyProperties properties() { return props; }
    public Clock clock() { return clock; }
    public WatermarkStore store() { return store; }
    public TokenSigner signer() { return signer; }
}
