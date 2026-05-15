/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe denial counters. Always active with near-zero overhead.
 *
 * <p>Counters are incremented on every denial regardless of enforcement mode. They provide
 * programmatic visibility into denial activity, complementing log output. Exposed via JMX when the
 * agent is loaded.
 *
 * <p>All methods are safe to call from any thread without synchronization.
 */
public final class DenialCounters {

  private static final AtomicLong totalCount = new AtomicLong();
  private static final EnumMap<Operation, AtomicLong> perOperation = new EnumMap<>(Operation.class);

  static {
    for (Operation op : Operation.values()) {
      perOperation.put(op, new AtomicLong());
    }
  }

  private DenialCounters() {}

  /** Increments counters for a denial. Called from BootstrapEnforcer on every denial. */
  static void increment(Operation op) {
    totalCount.incrementAndGet();
    perOperation.get(op).incrementAndGet();
  }

  /** Returns the total denial count across all operations. */
  public static long totalCount() {
    return totalCount.get();
  }

  /** Returns the denial count for a specific operation. */
  public static long count(Operation op) {
    return perOperation.get(op).get();
  }

  /** Returns an immutable snapshot of all per-operation counts. */
  public static Map<Operation, Long> snapshot() {
    EnumMap<Operation, Long> result = new EnumMap<>(Operation.class);
    perOperation.forEach((op, counter) -> result.put(op, counter.get()));
    return Map.copyOf(result);
  }

  /** Resets all counters to zero. Primarily for testing. */
  public static void reset() {
    totalCount.set(0);
    perOperation.values().forEach(c -> c.set(0));
  }
}
