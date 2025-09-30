package io.veggieshop.platform.application.consistency;

import io.veggieshop.platform.application.consistency.token.ConsistencyToken;
import io.veggieshop.platform.application.consistency.token.TokenSigner;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * ConsistencyService provides per-tenant read-your-writes consistency.
 *
 * <p>Framework-agnostic core that:
 *
 * <ul>
 *   <li>Tracks a per-tenant "watermark" of the last observed write.
 *   <li>Parses/verifies client-sent consistency tokens and enforces tenant consistency.
 *   <li>Emits new tokens for responses binding the (tenant, watermark).
 *   <li>Maintains per-request state via a {@link ThreadLocal} scope.
 * </ul>
 *
 * <p>{@code WatermarkStore} is pluggable; a default in-memory implementation is provided for
 * tests/dev.
 */
public final class ConsistencyService {

  // ----------------- SPI: Watermark store -----------------

  /** Abstraction for the per-tenant watermark (monotonic timestamp, epoch millis). */
  public interface WatermarkStore {

    /**
     * Returns the current watermark for the tenant, or {@code 0} if none.
     *
     * @param tenant tenant identifier
     * @return watermark value in epoch millis
     */
    long current(String tenant);

    /**
     * Advances the tenant's watermark to at least the provided epoch millis.
     *
     * @param tenant tenant identifier
     * @param epochMillis lower bound to advance to (epoch millis)
     * @return the updated watermark value
     */
    long advanceAtLeast(String tenant, long epochMillis);

    /**
     * Advances the tenant's watermark to "now" using the service clock.
     *
     * @param tenant tenant identifier
     * @return the updated watermark value
     */
    long advanceToNow(String tenant);
  }

  /** Simple single-node store. Replace with Redis/Kafka etc. in production. */
  public static final class InMemoryWatermarkStore implements WatermarkStore {
    private final Clock clock;
    private final ConcurrentHashMap<String, AtomicLong> map = new ConcurrentHashMap<>();

    public InMemoryWatermarkStore(Clock clock) {
      this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public long current(String tenant) {
      return map.computeIfAbsent(tenant, t -> new AtomicLong()).get();
    }

    @Override
    public long advanceAtLeast(String tenant, long epochMillis) {
      return map.computeIfAbsent(tenant, t -> new AtomicLong())
          .accumulateAndGet(epochMillis, Math::max);
    }

    @Override
    public long advanceToNow(String tenant) {
      return advanceAtLeast(tenant, clock.millis());
    }

    @Override
    public String toString() {
      return "InMemoryWatermarkStore{size=" + map.size() + "}";
    }
  }

  // ----------------- Request state -----------------

  /** Thread-local request scope state. */
  public static final class RequestState {
    private final String tenant;
    private final Optional<ConsistencyToken> ifConsistentWith;
    private final Optional<ConsistencyToken> priorToken;
    private final long startedAtMillis;

    RequestState(
        String tenant,
        Optional<ConsistencyToken> ifConsistentWith,
        Optional<ConsistencyToken> priorToken,
        long startedAtMillis) {
      this.tenant = tenant;
      this.ifConsistentWith = ifConsistentWith;
      this.priorToken = priorToken;
      this.startedAtMillis = startedAtMillis;
    }

    /** Returns the tenant identifier for this request. */
    public String tenant() {
      return tenant;
    }

    /** Returns the parsed {@code If-Consistent-With} token, if present. */
    public Optional<ConsistencyToken> ifConsistentWith() {
      return ifConsistentWith;
    }

    /** Returns the parsed prior response token, if present. */
    public Optional<ConsistencyToken> priorToken() {
      return priorToken;
    }

    /** Returns the request start time in epoch millis. */
    public long startedAtMillis() {
      return startedAtMillis;
    }

    /** Watermark the client wants us to read at/after. */
    public long requiredWatermarkOrZero() {
      return ifConsistentWith.map(ConsistencyToken::watermarkMillis).orElse(0L);
    }
  }

  /** Scope that restores prior request state on close. */
  public final class Scope implements AutoCloseable {
    private final RequestState previous;

    private Scope(RequestState prev) {
      this.previous = prev;
    }

    /** Restores the previous thread-local request state. */
    @Override
    public void close() {
      TL.set(previous);
    }
  }

  // ----------------- Fields -----------------

  private final TokenSigner signer;
  private final ConsistencyProperties props;
  private final Clock clock;
  private final WatermarkStore store;

  /** Per-thread request state. */
  private static final ThreadLocal<RequestState> TL = new ThreadLocal<>();

  // ----------------- Construction -----------------

  /**
   * Creates a new {@code ConsistencyService}.
   *
   * @param signer token signer for encoding/verification
   * @param props consistency properties (TTL, skew, etc.)
   * @param clock time source
   * @param store watermark store implementation
   */
  public ConsistencyService(
      TokenSigner signer, ConsistencyProperties props, Clock clock, WatermarkStore store) {
    this.signer = Objects.requireNonNull(signer, "signer");
    this.props = Objects.requireNonNull(props, "props");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.store = Objects.requireNonNull(store, "store");
  }

  /**
   * Convenient factory using the in-memory store (tests/dev).
   *
   * @param signer token signer
   * @param props properties
   * @param clock time source
   * @return configured service bound to an {@link InMemoryWatermarkStore}.
   */
  public static ConsistencyService withInMemoryStore(
      TokenSigner signer, ConsistencyProperties props, Clock clock) {
    return new ConsistencyService(signer, props, clock, new InMemoryWatermarkStore(clock));
  }

  // ----------------- Request lifecycle -----------------

  /**
   * Opens a request scope.
   *
   * <p>Parses/verifies {@code If-Consistent-With} and prior token (X-Consistency-Token), enforces
   * tenant match, and seeds the watermark from the prior token when newer.
   *
   * @param tenant tenant identifier
   * @param ifConsistentWithCompact compact If-Consistent-With token, may be null/blank
   * @param priorTokenCompact compact prior token, may be null/blank
   * @return scope that restores the previous state when closed
   */
  public Scope openRequest(
      String tenant, String ifConsistentWithCompact, String priorTokenCompact) {
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

  /** Returns the current request state, if any. */
  public Optional<RequestState> currentRequest() {
    return Optional.ofNullable(TL.get());
  }

  /** Returns the current tenant from the thread-local scope, if any. */
  public Optional<String> currentTenant() {
    RequestState s = TL.get();
    return s == null ? Optional.empty() : Optional.of(s.tenant());
  }

  // ----------------- Token operations -----------------

  /**
   * Parses and verifies a compact token, enforcing tenant match and TTL.
   *
   * @param compact compact token string
   * @param expectedTenant tenant that must match the token
   * @return valid token if acceptable; otherwise empty
   */
  public Optional<ConsistencyToken> parseValidForTenant(String compact, String expectedTenant) {
    if (compact == null || compact.isBlank()) {
      return Optional.empty();
    }
    Optional<ConsistencyToken> tok = ConsistencyToken.parseAndVerify(compact, signer);
    if (tok.isEmpty()) {
      return Optional.empty();
    }
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

  /**
   * Emits a compact token for the given tenant using the store watermark (and optional entity
   * version).
   *
   * @param tenant tenant identifier
   * @param entityVersionOrNull optional entity version to embed, may be {@code null}
   * @return compact, signed token string
   */
  public String emitTokenForTenant(String tenant, Long entityVersionOrNull) {
    long wm = store.current(tenant);
    ConsistencyToken token = ConsistencyToken.of(tenant, clock.millis(), wm, entityVersionOrNull);
    return token.encode(signer);
  }

  /**
   * Emits a token for the current request tenant.
   *
   * @param entityVersionOrNull optional entity version to embed, may be {@code null}
   * @return compact, signed token string
   * @throws IllegalStateException if there is no current request scope
   */
  public String emitTokenForCurrentTenant(Long entityVersionOrNull) {
    String tenant =
        currentTenant().orElseThrow(() -> new IllegalStateException("No request scope"));
    return emitTokenForTenant(tenant, entityVersionOrNull);
  }

  // ----------------- Watermark operations -----------------

  /**
   * Advances the tenant watermark to "now" after a successful write.
   *
   * @param tenant tenant identifier
   * @return updated watermark value
   */
  public long markWriteNow(String tenant) {
    return store.advanceToNow(tenant);
  }

  /**
   * Advances the current request tenant's watermark to "now".
   *
   * @return updated watermark value
   * @throws IllegalStateException if there is no current request scope
   */
  public long markWriteNow() {
    String tenant =
        currentTenant().orElseThrow(() -> new IllegalStateException("No request scope"));
    return store.advanceToNow(tenant);
  }

  /**
   * Returns the current watermark for the provided tenant.
   *
   * @param tenant tenant identifier
   * @return watermark value in epoch millis
   */
  public long currentWatermark(String tenant) {
    return store.current(tenant);
  }

  /**
   * Returns the current watermark for the current request tenant, or {@code 0} if no scope.
   *
   * @return watermark value in epoch millis, or {@code 0} if no scope
   */
  public long currentWatermarkOrZero() {
    RequestState s = TL.get();
    return (s == null) ? 0L : store.current(s.tenant());
  }

  // ----------------- Accessors -----------------

  /** Returns the configured consistency properties. */
  public ConsistencyProperties properties() {
    return props;
  }

  /** Returns the service clock. */
  public Clock clock() {
    return clock;
  }

  /** Returns the underlying watermark store. */
  public WatermarkStore store() {
    return store;
  }

  /** Returns the token signer used for encoding/verification. */
  public TokenSigner signer() {
    return signer;
  }
}
