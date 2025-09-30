package io.veggieshop.platform.application.consistency;

import java.time.Duration;
import java.util.Objects;

/**
 * ConsistencyProperties
 *
 * <p>Immutable configuration for the consistency subsystem (token TTL, RYW wait tuning, clock
 * skew).
 */
public final class ConsistencyProperties {

  /** Default values chosen for low latency APIs. */
  public static final Duration DEFAULT_TOKEN_TTL = Duration.ofMinutes(10);

  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);
  public static final Duration DEFAULT_RYW_MAX_WAIT = Duration.ofSeconds(2);
  public static final Duration DEFAULT_RYW_INITIAL_POLL = Duration.ofMillis(20);
  public static final Duration DEFAULT_RYW_MAX_POLL = Duration.ofMillis(150);

  private final Duration tokenTtl;
  private final Duration clockSkew;
  private final Duration rywMaxWait;
  private final Duration rywInitialPoll;
  private final Duration rywMaxPoll;

  private ConsistencyProperties(Builder b) {
    this.tokenTtl = requirePositive(b.tokenTtl, "tokenTtl");
    this.clockSkew = requirePositive(b.clockSkew, "clockSkew");
    this.rywMaxWait = requirePositive(b.rywMaxWait, "rywMaxWait");
    this.rywInitialPoll = requirePositive(b.rywInitialPoll, "rywInitialPoll");
    this.rywMaxPoll = requirePositive(b.rywMaxPoll, "rywMaxPoll");
  }

  /**
   * Returns a builder pre-populated with sane defaults.
   *
   * @return new {@link Builder} instance with defaults applied
   */
  public static Builder builder() {
    return new Builder()
        .tokenTtl(DEFAULT_TOKEN_TTL)
        .clockSkew(DEFAULT_CLOCK_SKEW)
        .rywMaxWait(DEFAULT_RYW_MAX_WAIT)
        .rywInitialPoll(DEFAULT_RYW_INITIAL_POLL)
        .rywMaxPoll(DEFAULT_RYW_MAX_POLL);
  }

  public Duration tokenTtl() {
    return tokenTtl;
  }

  public Duration clockSkew() {
    return clockSkew;
  }

  public Duration rywMaxWait() {
    return rywMaxWait;
  }

  public Duration rywInitialPoll() {
    return rywInitialPoll;
  }

  public Duration rywMaxPoll() {
    return rywMaxPoll;
  }

  private static Duration requirePositive(Duration d, String name) {
    Objects.requireNonNull(d, name);
    if (d.isZero() || d.isNegative()) {
      throw new IllegalArgumentException(name + " must be > 0");
    }
    return d;
  }

  // -------- Builder --------

  /** Fluent builder for {@link ConsistencyProperties}. Not thread-safe. */
  public static final class Builder {
    private Duration tokenTtl;
    private Duration clockSkew;
    private Duration rywMaxWait;
    private Duration rywInitialPoll;
    private Duration rywMaxPoll;

    private Builder() {}

    /** Sets token time-to-live. */
    public Builder tokenTtl(Duration v) {
      this.tokenTtl = v;
      return this;
    }

    /** Sets tolerated clock skew. */
    public Builder clockSkew(Duration v) {
      this.clockSkew = v;
      return this;
    }

    /** Sets maximum read-your-writes wait duration. */
    public Builder rywMaxWait(Duration v) {
      this.rywMaxWait = v;
      return this;
    }

    /** Sets initial poll backoff for read-your-writes. */
    public Builder rywInitialPoll(Duration v) {
      this.rywInitialPoll = v;
      return this;
    }

    /** Sets maximum poll backoff for read-your-writes. */
    public Builder rywMaxPoll(Duration v) {
      this.rywMaxPoll = v;
      return this;
    }

    /** Builds an immutable {@link ConsistencyProperties} instance. */
    public ConsistencyProperties build() {
      return new ConsistencyProperties(this);
    }
  }

  @Override
  public String toString() {
    return "ConsistencyProperties{tokenTtl="
        + tokenTtl
        + ", clockSkew="
        + clockSkew
        + ", rywMaxWait="
        + rywMaxWait
        + ", rywInitialPoll="
        + rywInitialPoll
        + ", rywMaxPoll="
        + rywMaxPoll
        + "}";
  }
}
