/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.management.ThreadMXBean;
import java.lang.management.ManagementFactory;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A denial storm must stay cheap without ever becoming permissive.
 *
 * <p>Describing a denial costs far more than making one -- a formatted message, an accumulated
 * record, a stack and a log line. A single missing entitlement on an initialisation path can be
 * denied hundreds of thousands of times a second, and that has exhausted the heap of the very
 * application the agent was protecting. The agent killed its host.
 *
 * <p>The guard bounds what a denial costs to describe. It must never bound what is denied:
 * degrading enforcement under load would make jGuard fail open exactly when it is under pressure,
 * which is an attacker-triggerable bypass. Both halves are asserted here, and the second matters
 * more than the first.
 */
class DenialStormRegressionTest {

  /**
   * Bytes a suppressed denial may add <em>over an allowed call</em> before this is a regression.
   *
   * <p>Deliberately a delta rather than an absolute. Interception has a base cost -- attribution
   * walks the stack on every operation whatever the verdict -- and charging that to the denial
   * measures the wrong thing: an absolute ceiling here fails or passes based on the cost of the
   * stack walk, which this test does not govern and which {@code
   * CallerAttributionCostRegressionTest} does. What belongs to this test is the increment, and once
   * detail is suppressed the increment is two atomic increments and a throw of a shared stackless
   * instance, which measures as zero.
   */
  private static final long MAX_BYTES_ADDED_BY_SUPPRESSED_DENIAL = 64L;

  private static final int ITERATIONS = 50_000;

  @BeforeEach
  void reset() {
    DenialStormGuard.reset();
    DenialCounters.reset();
  }

  @AfterEach
  void restore() {
    BootstrapEnforcer.setCallback(null);
    BootstrapEnforcer.setMode(EnforcementMode.STRICT);
    DenialStormGuard.setDetail(null);
    DenialStormGuard.reset();
  }

  @Test
  @DisplayName("every denial in a storm is still denied")
  void stormStillDeniesEverything() {
    AtomicLong denialsRequested = new AtomicLong();
    AtomicLong denialsThrown = new AtomicLong();

    BootstrapEnforcer.setMode(EnforcementMode.STRICT);
    BootstrapEnforcer.setCallback(
        (caller, op, arg0, arg1) -> {
          denialsRequested.incrementAndGet();
          return new SecurityException("denied for test");
        });

    for (int i = 0; i < ITERATIONS; i++) {
      try {
        BootstrapEnforcer.onPropertyRead("java.version");
      } catch (SecurityException expected) {
        denialsThrown.incrementAndGet();
      }
    }

    assertThat(denialsThrown.get())
        .as(
            "the guard suppressed detail for some denials; it must never suppress the denial"
                + " itself, or a storm becomes a way to turn enforcement off")
        .isEqualTo(denialsRequested.get());
    assertThat(denialsThrown.get()).isPositive();
  }

  @Test
  @DisplayName("bootstrap adds nothing to an already-suppressed denial")
  void suppressedDenialCostsNothingInBootstrap() {
    BootstrapEnforcer.setMode(EnforcementMode.STRICT);

    // This is what a storming PolicyEnforcer returns. The decision to suppress is the enforcer's --
    // it owns the policy and the window -- so this half of the path is only asked to recognise the
    // shared instance and skip every describing step: no formatted args, no accumulated record, no
    // log line. What is left is the unconditional counters (two atomics) and the throw itself, and
    // neither allocates. A regression here means a describing step escaped the detail branch.
    //
    // Note this deliberately does NOT construct its own SecurityException. Doing so would replace
    // PolicyEnforcer rather than stand in for it, and would measure the stack captured by the
    // test's
    // own throw instead of the code under test.
    //
    // Both arms install a callback. A null callback makes dispatch() return early as "agent not
    // initialised", which measures nothing at all -- the arms must differ only in the verdict.
    BootstrapEnforcer.setCallback((caller, op, arg0, arg1) -> null);
    long allowed = measureDispatch();

    BootstrapEnforcer.setCallback((caller, op, arg0, arg1) -> SuppressedDenial.INSTANCE);
    long suppressed = measureDispatch();

    long added = suppressed - allowed;
    assertThat(added)
        .as(
            "a suppressed denial added %d bytes over an allowed call (ceiling %d; allowed %d,"
                + " denied %d). Everything that describes a denial must stay behind the detail"
                + " branch, or suppression buys nothing.",
            added, MAX_BYTES_ADDED_BY_SUPPRESSED_DENIAL, allowed, suppressed)
        .isLessThanOrEqualTo(MAX_BYTES_ADDED_BY_SUPPRESSED_DENIAL);
  }

  /** Drives the enforcer under whatever callback is installed and returns bytes per call. */
  private long measureDispatch() {
    for (int i = 0; i < 20_000; i++) {
      try {
        BootstrapEnforcer.onPropertyRead("java.version");
      } catch (SecurityException ignored) {
        // expected when the installed callback denies
      }
    }

    ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
    long id = Thread.currentThread().threadId();
    long before = threads.getThreadAllocatedBytes(id);
    for (int i = 0; i < ITERATIONS; i++) {
      try {
        BootstrapEnforcer.onPropertyRead("java.version");
      } catch (SecurityException ignored) {
        // expected when the installed callback denies
      }
    }
    return (threads.getThreadAllocatedBytes(id) - before) / ITERATIONS;
  }

  @Test
  @DisplayName("ALWAYS never suppresses and NEVER always suppresses")
  void detailLevelsAreHonoured() {
    BootstrapEnforcer.setMode(EnforcementMode.STRICT);

    DenialStormGuard.setDetail(DenialDetail.ALWAYS);
    for (int i = 0; i < 5_000; i++) {
      assertThat(DenialStormGuard.shouldDetail("mod", Operation.PROP_READ))
          .as("ALWAYS must keep full detail however many denials occur -- it is the RCA setting")
          .isTrue();
    }

    DenialStormGuard.setDetail(DenialDetail.NEVER);
    assertThat(DenialStormGuard.shouldDetail("mod", Operation.PROP_READ))
        .as("NEVER must take the cheap path from the first denial")
        .isFalse();
  }

  @Test
  @DisplayName("adaptive keeps detail for an ordinary burst")
  void adaptiveKeepsDetailForSmallBursts() {
    DenialStormGuard.setDetail(DenialDetail.ADAPTIVE);

    // A handful of denials is a policy gap worth reading, not a storm worth silencing.
    for (int i = 0; i < 50; i++) {
      assertThat(DenialStormGuard.shouldDetail("quiet.module", Operation.FS_READ))
          .as("an ordinary burst must keep full detail, or the guard hides the thing it exists for")
          .isTrue();
    }
    assertThat(DenialStormGuard.suppressedCount("quiet.module", Operation.FS_READ)).isZero();
  }
}
