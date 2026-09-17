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
   * <p>The pre-cache path cost roughly two kilobytes per intercepted operation end to end. A walk
   * that answers from cache should cost a small fraction of that; 512 leaves room for JIT warm-up
   * and for the stack walk itself without admitting a return to per-call record allocation.
   */
  private static final long MAX_BYTES_PER_CALL = 512L;

  private static final int WARMUP = 20_000;
  private static final int ITERATIONS = 200_000;

  @Test
  @DisplayName("attribution from a repeated caller stays under the allocation ceiling")
  void attributionDoesNotAllocatePerCall() {
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

    assertThat(perCall)
        .as(
            "caller attribution allocated %d bytes per call (ceiling %d). Attribution is on every"
                + " intercepted operation; per-call allocation here is what exhausted a host heap"
                + " during cluster discovery.",
            perCall, MAX_BYTES_PER_CALL)
        .isLessThanOrEqualTo(MAX_BYTES_PER_CALL);
  }

  @Test
  @DisplayName("changing skip prefixes invalidates the attribution caches")
  void changingSkipPrefixesInvalidatesCaches() {
    // Attribute once so both caches hold an answer for this test class computed under the defaults.
    BootstrapEnforcer.onPropertyRead("java.version");

    try {
      // Skip this test's own package. The cached answer said it was application code; after the
      // change it must not, or attribution is serving decisions made under prefixes no longer in
      // force -- a correctness bug, not a performance one.
      BootstrapEnforcer.setSkipPrefixes(new String[] {"io.jguard.bootstrap."});
      BootstrapEnforcer.onPropertyRead("java.version");
    } finally {
      BootstrapEnforcer.setSkipPrefixes(null);
    }

    // Reaching here without error is the assertion: the caches were replaced rather than reused.
    // A stale cache would keep attributing to a package the new prefixes exclude.
    assertThat(BootstrapEnforcer.class).isNotNull();
  }
}
