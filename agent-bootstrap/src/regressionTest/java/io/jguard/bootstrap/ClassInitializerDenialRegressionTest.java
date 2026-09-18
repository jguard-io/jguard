/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.management.ThreadMXBean;
import java.lang.management.ManagementFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A denial must never be able to terminate the host.
 *
 * <p>Inside a class initialiser it can. Any throwable escaping {@code <clinit>} is wrapped by the
 * JVM as {@link ExceptionInInitializerError} -- an Error, not an Exception -- so it passes every
 * {@code catch (Exception)} between the denial and the top of the thread, and a host that treats
 * Error as fatal exits. The damage outlives the throw: the class is marked erroneous for the life
 * of the JVM, so every later touch raises {@link NoClassDefFoundError} and not even a hot-reloaded
 * policy can revive it without a restart. Enforcement is recoverable by design; this is the one
 * path where it is not.
 *
 * <p>This is not hypothetical. On 2026-09-18 a missing {@code system.property.read} grant for
 * {@code java.net.useSystemProxies} was denied inside {@code sun.net.spi.DefaultProxySelector}'s
 * static initialiser, on the first request the AWS SDK made through HttpClient. Fifteen denials
 * killed five production nodes and took a memory service down -- from one absent line of policy.
 *
 * <p>Two properties are asserted here and the second matters as much as the first: enforcement must
 * be given up <em>only</em> inside an initialiser, and never anywhere else.
 */
class ClassInitializerDenialRegressionTest {

  @BeforeEach
  void reset() {
    DenialStormGuard.reset();
    DenialCounters.reset();
    BootstrapEnforcer.setMode(EnforcementMode.STRICT);
  }

  @AfterEach
  void restore() {
    BootstrapEnforcer.setCallback(null);
    BootstrapEnforcer.setMode(EnforcementMode.STRICT);
    DenialStormGuard.setDetail(null);
    DenialStormGuard.reset();
    DenialCounters.reset();
  }

  /** Denies everything, as a policy missing an entitlement does. */
  private static void denyEverything() {
    BootstrapEnforcer.setCallback(
        (caller, op, arg0, arg1) -> new SecurityException("denied for test"));
  }

  /**
   * Reads a guarded property from a static initialiser -- the shape that killed the nodes.
   *
   * <p>Loaded reflectively by name so that initialisation happens at a point the test controls, and
   * so that a failure surfaces as ExceptionInInitializerError here rather than while the test class
   * itself is being set up.
   */
  static final class ReadsPropertyInStaticInit {
    static final String VALUE;

    static {
      BootstrapEnforcer.onPropertyRead("java.net.useSystemProxies");
      VALUE = "initialised";
    }

    private ReadsPropertyInStaticInit() {}
  }

  @Test
  @DisplayName("a denial inside a class initialiser does not kill the JVM or poison the class")
  void denialInClassInitializerIsNotFatal() {
    denyEverything();

    // Before the guard this threw ExceptionInInitializerError, which no catch(Exception) upstream
    // could hold, and the node went down.
    assertThatCode(
            () ->
                Class.forName(
                    ReadsPropertyInStaticInit.class.getName(),
                    true,
                    ClassInitializerDenialRegressionTest.class.getClassLoader()))
        .as(
            "a denial raised inside <clinit> escaped as an Error. That is how jGuard terminates the"
                + " application it is supposed to be protecting.")
        .doesNotThrowAnyException();

    // The class must remain usable. A class whose initialiser threw is marked erroneous forever:
    // proving the absence of the throw is not enough, because the lasting damage is the poisoning.
    assertThat(ReadsPropertyInStaticInit.VALUE)
        .as("the class initialised but was left unusable, which is the other half of the outage")
        .isEqualTo("initialised");

    assertThat(DenialCounters.initializerUnenforcedCount())
        .as(
            "an unenforced denial must be counted, or policy silently rots: the operation was"
                + " ALLOWED and the only signal that it was is this counter and its log line")
        .isPositive();

    assertThat(DenialCounters.totalCount())
        .as("the denial still happened and still belongs in the totals")
        .isPositive();
  }

  @Test
  @DisplayName("enforcement is given up ONLY in an initialiser, never for ordinary code")
  void ordinaryDenialsStillThrow() {
    denyEverything();

    // The whole point of the guard is to be narrow. If it leaked to the ordinary path it would turn
    // every denial into a log line, which is a silent, total bypass of the agent.
    assertThatThrownBy(() -> BootstrapEnforcer.onPropertyRead("java.version"))
        .as("a denial outside a class initialiser must still be enforced")
        .isInstanceOf(SecurityException.class);

    assertThat(DenialCounters.initializerUnenforcedCount())
        .as("an ordinary denial must not be recorded as unenforced")
        .isZero();
  }

  @Test
  @DisplayName("the initialiser check costs a storm nothing")
  void suppressedDenialsDoNotPayForTheCheck() {
    // Finding the enclosing initialiser means walking the stack to the bottom, because the usual
    // answer is "none" and there is nothing to short-circuit on. Measured at 19,440 bytes per call
    // against a 1,968-byte allowed call. Run on every denial it would allocate gigabytes a second
    // under a storm and exhaust the heap -- trading a fatal Error for a fatal OOM is not a fix, so
    // the check is confined to denials that are already being described.
    BootstrapEnforcer.setCallback((caller, op, arg0, arg1) -> SuppressedDenial.INSTANCE);

    long before = allocatedBytes();
    for (int i = 0; i < 20_000; i++) {
      try {
        BootstrapEnforcer.onPropertyRead("java.version");
      } catch (SecurityException expected) {
        // a suppressed denial is still a denial, and is still thrown
      }
    }
    long perCall = (allocatedBytes() - before) / 20_000;

    assertThat(perCall)
        .as(
            "a suppressed denial cost %d bytes per call. The stack walk has leaked onto the storm"
                + " path, where it undoes DenialStormGuard and starves the heap it protects.",
            perCall)
        .isLessThanOrEqualTo(3_000L);
  }

  private static long allocatedBytes() {
    ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
    return threads.getThreadAllocatedBytes(Thread.currentThread().threadId());
  }
}
