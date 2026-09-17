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
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Caller attribution must not allocate per call.
 *
 * <p>Attribution runs on every intercepted operation -- every property read, file open, socket
 * connect and thread start the host JVM performs. It used to build a {@link StackWalker} per call,
 * run a stream pipeline through it, allocate a record for the result and then a second record to
 * hand across the callback boundary. On a node whose policy did not cover one of its own modules
 * that was enough to exhaust a 1g heap during cluster discovery: the agent killed the application
 * it was guarding.
 *
 * <p>Attribution is a pure function of the calling class, so it is now answered from a {@link
 * ClassValue} and the steady-state cost is the walk alone. This test pins that: a repeated call
 * from an already-seen class must stay far below what the old path cost.
 *
 * <p>Allocation is measured rather than wall clock, because allocation is what ran the heap out and
 * because it is far less noisy on shared CI hardware. The ceiling is generous on purpose -- it is
 * there to catch a return to per-call allocation, not to police small changes.
 */
class CallerAttributionCostRegressionTest {

  /**
   * Bytes per attribution above which this is considered regressed.
   *
   * <p>This pins today's measured cost against getting worse. It is not a target, and it is
   * deliberately not the 512 it used to be: that figure was never calibrated, because the test that
   * carried it never installed a callback and so measured an early return of zero bytes rather than
   * an interception. Against a live enforcer the same path measures about 1968.
   *
   * <p>Where those bytes go is only partly understood. Measured in isolation, the re-entrancy
   * {@code ThreadLocal} accounts for 32 and the stream pipeline in {@code determineCallerContext}
   * for about 220 of the walk's 924; roughly half the total is not yet attributed to anything, most
   * likely the walk scaling with stack depth, which is far greater under a real interception than
   * under a test. Reducing it is worth doing -- it is charged to every property read, file open and
   * socket connect the host makes, whatever the verdict -- but it is a separate change from the
   * storm guard, and guessing at it has already produced three wrong answers.
   *
   * <p>What this ceiling still catches, which is what it was written for, is a return to allocating
   * a record per call: that path cost multiple kilobytes and exhausted a host heap during cluster
   * discovery.
   */
  private static final long MAX_BYTES_PER_CALL = 2_560L;

  private static final int WARMUP = 20_000;
  private static final int ITERATIONS = 200_000;

  @Test
  @DisplayName("attribution from a repeated caller stays under the allocation ceiling")
  void attributionDoesNotAllocatePerCall() {
    // A callback MUST be installed. dispatch() returns at once when none is -- "agent not
    // initialised" -- so the loop below would never reach attribution, and this test would pass
    // however much attribution allocated. It did exactly that: it measured 0 bytes per call against
    // a ceiling of 512, while a real dispatch cost 1984. A test that cannot fail reads as coverage
    // and is worse than no test, so the non-vacuity assertion below is not optional.
    BootstrapEnforcer.setCallback((caller, op, arg0, arg1) -> null);

    try {
      ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
      long id = Thread.currentThread().threadId();

      for (int i = 0; i < WARMUP; i++) {
        BootstrapEnforcer.onPropertyRead("java.version");
      }

      long before = threads.getThreadAllocatedBytes(id);
      for (int i = 0; i < ITERATIONS; i++) {
        BootstrapEnforcer.onPropertyRead("java.version");
      }
      long allocated = threads.getThreadAllocatedBytes(id) - before;
      long perCall = allocated / ITERATIONS;

      assertThat(allocated)
          .as(
              "measured 0 bytes, which means the enforcer never ran -- almost certainly a missing"
                  + " callback making dispatch() return early. The measurement is vacuous and the"
                  + " ceiling below would pass no matter what attribution cost.")
          .isPositive();

      assertThat(perCall)
          .as(
              "caller attribution allocated %d bytes per call (ceiling %d). Attribution is on every"
                  + " intercepted operation; per-call allocation here is what exhausted a host heap"
                  + " during cluster discovery.",
              perCall, MAX_BYTES_PER_CALL)
          .isLessThanOrEqualTo(MAX_BYTES_PER_CALL);
    } finally {
      BootstrapEnforcer.setCallback(null);
    }
  }

  @Test
  @DisplayName("changing skip prefixes invalidates the attribution caches")
  void changingSkipPrefixesInvalidatesCaches() {
    List<CallerContext> seen = new ArrayList<>();
    BootstrapEnforcer.setCallback(
        (caller, op, arg0, arg1) -> {
          seen.add(caller);
          return null;
        });

    try {
      // Attribute once under the defaults, so both caches hold an answer for this class.
      BootstrapEnforcer.onPropertyRead("java.version");
      assertThat(seen)
          .as("the test class should be attributed as application code under default prefixes")
          .isNotEmpty();
      String underDefaults = seen.get(seen.size() - 1).packageName();

      // Now exclude whatever package attribution just resolved to, plus the defaults that got us
      // there. Attribution must re-evaluate and walk past it to the next application frame. If the
      // caches were reused it would keep reporting the excluded package -- an answer computed under
      // prefixes no longer in force.
      BootstrapEnforcer.setSkipPrefixes(
          new String[] {
            "io.jguard.bootstrap.", "io.jguard.agent.", "java.", "sun.", "jdk.", underDefaults
          });
      BootstrapEnforcer.onPropertyRead("java.version");

      assertThat(seen).hasSizeGreaterThan(1);
      String afterChange = seen.get(seen.size() - 1).packageName();

      assertThat(afterChange)
          .as(
              "attribution still reported %s after that package was excluded, so a cached answer"
                  + " outlived the prefixes it was computed under",
              underDefaults)
          .isNotEqualTo(underDefaults);
    } finally {
      BootstrapEnforcer.setSkipPrefixes(null);
      BootstrapEnforcer.setCallback(null);
    }
  }
}
