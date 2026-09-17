/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.management.ThreadMXBean;
import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.CallerContext;
import io.jguard.bootstrap.DenialDetail;
import io.jguard.bootstrap.DenialStormGuard;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.bootstrap.Operation;
import io.jguard.bootstrap.SuppressedDenial;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What a denial costs the host application, measured against the real enforcer.
 *
 * <p>This is the test that decides whether the storm guard was worth adding, so it deliberately
 * exercises {@link PolicyEnforcer#check} rather than a stand-in. An earlier version of this
 * measurement installed its own callback returning {@code new SecurityException("denied")}; because
 * the callback <em>is</em> the enforcer, that replaced every guarded exit with a lambda and
 * measured the stack captured by the test's own throw. It could not have passed, and the number it
 * produced described nothing.
 *
 * <p>Both paths are measured in the same JVM, seconds apart, under the same JIT state: {@link
 * DenialDetail#ALWAYS} for the full describing path and {@link DenialDetail#NEVER} for the
 * suppressed one. A cross-run comparison against a separately built jar would be at the mercy of
 * compilation differences and of whether the jar under test was the one actually built.
 *
 * <p>{@code NEVER} is used rather than {@code ADAPTIVE} so the measurement cannot straddle a window
 * boundary, where {@code Window.record} emits a log line on trip and on reset. The adaptive
 * transition itself is covered by {@code DenialStormRegressionTest}.
 */
class DenialStormCostRegressionTest {

  /**
   * Bytes per denial, once detail is suppressed, above which this is considered regressed.
   *
   * <p>Suppression cannot reach zero: the policy lookup that reaches a denial decision still runs,
   * and that cost is not suppressible by design -- the guard bounds what a denial costs to
   * <em>describe</em>, never whether it is made. The ceiling is here to catch a describing step
   * escaping back onto the hot path.
   */
  private static final long MAX_BYTES_PER_SUPPRESSED_DENIAL = 512L;

  private static final String MODULE = "com.example.app";
  private static final int WARMUP = 20_000;
  private static final int ITERATIONS = 50_000;

  @TempDir Path tempDir;

  private PolicyEnforcer enforcer;
  private CallerContext caller;

  @BeforeEach
  void setUp() {
    // A policy that grants a filesystem read and nothing else, so a property read reaches a denial
    // through the ordinary lookup rather than through a missing-module short circuit.
    Entitlement entitlement =
        new Entitlement(
            SubjectPattern.module(),
            CapabilityGrant.of(
                "fs.read",
                List.of(
                    new CapabilityArgument.StringArg("/tmp"),
                    new CapabilityArgument.StringArg("**"))));
    PolicyDescriptor policy = PolicyDescriptor.create(MODULE, List.of(entitlement));
    AgentConfig config =
        new AgentConfig.Builder()
            .policyPath(tempDir.resolve("policy.bin"))
            .mode(EnforcementMode.STRICT)
            .build();
    enforcer = new PolicyEnforcer(policy, config);
    caller = new CallerContext("com.example.app.internal", MODULE);
    DenialStormGuard.reset();
  }

  @AfterEach
  void tearDown() {
    DenialStormGuard.setDetail(null);
    DenialStormGuard.reset();
  }

  @Test
  @DisplayName("suppressing detail cuts what a storming denial allocates")
  void suppressedDenialsAllocateFarLess() {
    long full = measure(DenialDetail.ALWAYS);
    long suppressed = measure(DenialDetail.NEVER);

    // Reported on every run: this pair of numbers is the justification for the guard existing, and
    // a future change that erodes the gap should be readable in the build log without a profiler.
    System.out.printf(
        "denial cost: full detail %d B/call, suppressed %d B/call (%.1fx)%n",
        full, suppressed, suppressed == 0 ? Double.NaN : (double) full / suppressed);

    assertThat(suppressed)
        .as(
            "a suppressed denial allocated %d bytes (ceiling %d); full detail costs %d. This is the"
                + " path that exhausted a host heap during cluster discovery.",
            suppressed, MAX_BYTES_PER_SUPPRESSED_DENIAL, full)
        .isLessThanOrEqualTo(MAX_BYTES_PER_SUPPRESSED_DENIAL);

    assertThat(suppressed)
        .as("suppression must actually cost less than describing, or the guard buys nothing")
        .isLessThan(full);
  }

  @Test
  @DisplayName("a suppressed denial is still a denial")
  void suppressionNeverPermits() {
    DenialStormGuard.setDetail(DenialDetail.NEVER);

    for (int i = 0; i < 1_000; i++) {
      SecurityException denial = enforcer.check(caller, Operation.PROP_READ, "java.version", 0);
      assertThat(denial)
          .as(
              "the enforcer returned null while suppressing detail; a storm would then be a way to"
                  + " turn enforcement off, which is an attacker-triggerable bypass")
          .isNotNull();
      assertThat(denial)
          .as("a suppressed denial should be the shared stackless instance")
          .isSameAs(SuppressedDenial.INSTANCE);
    }
  }

  /** Runs the denial path at the given detail level and returns bytes allocated per call. */
  private long measure(DenialDetail level) {
    DenialStormGuard.setDetail(level);
    DenialStormGuard.reset();
    DenialStormGuard.setDetail(level);

    for (int i = 0; i < WARMUP; i++) {
      enforcer.check(caller, Operation.PROP_READ, "java.version", 0);
    }

    ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
    long id = Thread.currentThread().threadId();
    long before = threads.getThreadAllocatedBytes(id);
    for (int i = 0; i < ITERATIONS; i++) {
      enforcer.check(caller, Operation.PROP_READ, "java.version", 0);
    }
    return (threads.getThreadAllocatedBytes(id) - before) / ITERATIONS;
  }
}
