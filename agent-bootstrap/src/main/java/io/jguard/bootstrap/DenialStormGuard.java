/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounds the cost of a denial storm without ever bounding enforcement.
 *
 * <h2>Why this exists</h2>
 *
 * <p>A single missing entitlement on an initialisation path can be denied hundreds of thousands of
 * times per second. Each denial formats a message, builds a {@code SecurityException} with a full
 * stack trace, and writes a log line. That is several kilobytes per call, and it has exhausted the
 * heap of a host application before an operator could edit a policy file -- the agent killed the
 * process it was protecting.
 *
 * <h2>What it does NOT do</h2>
 *
 * <p>It does not degrade enforcement. Degrading STRICT to PERMISSIVE under load would make jGuard
 * fail <em>open</em> exactly when it is under pressure, which is an attacker-triggerable bypass:
 * provoke a storm, lose the guarantee. The decision is never changed, the exception type is never
 * changed, and the same operations are denied before and after this trips.
 *
 * <h2>What it does</h2>
 *
 * <p>It degrades the <em>cost</em> of denying. Past a threshold, for one {@code (module,
 * operation)} pair only, the caller is told to skip the parts that are merely observability:
 * message formatting, policy-name enumeration, stack capture and per-denial logging. The operation
 * is still denied and still throws.
 *
 * <p>Scoping per pair matters: one misbehaving package cannot suppress the detail that would
 * explain a different package's problem.
 *
 * <h2>Recovery</h2>
 *
 * <p>The window slides. When the rate falls below the threshold the pair returns to full detail on
 * its own, and says so. Nothing needs to be restarted and no policy needs to change.
 */
public final class DenialStormGuard {

  /**
   * Denials of one (module, operation) pair within one window before detail is suppressed.
   *
   * <p>High enough that ordinary bursts -- a retry loop, a noisy startup -- keep full detail, low
   * enough that the surviving allocation cannot exhaust a heap.
   */
  private static final int DEFAULT_THRESHOLD = 1_000;

  /** Length of the sliding window, in nanoseconds. */
  private static final long DEFAULT_WINDOW_NANOS = 10_000_000_000L; // 10s

  private static final String PROP_THRESHOLD = "jguard.denial.storm.threshold";
  private static final String PROP_WINDOW_SECONDS = "jguard.denial.storm.window";
  private static final String PROP_DETAIL = "jguard.denial.detail";

  private static final AgentLogger LOG = AgentLogger.getLogger(DenialStormGuard.class);

  private static volatile int threshold = readThreshold();
  private static volatile long windowNanos = readWindowNanos();
  private static volatile DenialDetail detail = DenialDetail.parse(System.getProperty(PROP_DETAIL));

  /** State per (module, operation). Bounded by policy size times operation count. */
  private static final Map<String, Window> WINDOWS = new ConcurrentHashMap<>();

  private DenialStormGuard() {}

  /**
   * Records a denial and reports whether full detail should still be produced.
   *
   * <p>Callers must not change their decision based on the result -- only how much they spend
   * describing it.
   *
   * @param moduleName the denied caller's module
   * @param op the denied operation
   * @return true to build the full message, stack and log line; false to use the cheap path
   */
  public static boolean shouldDetail(String moduleName, Operation op) {
    DenialDetail level = detail;
    if (level == DenialDetail.ALWAYS) {
      return true; // RCA: pay the allocation, see every denial
    }
    if (level == DenialDetail.NEVER) {
      return false; // acute pressure, or an already-diagnosed pair
    }
    if (threshold <= 0) {
      return true; // adaptive, but the window is disabled
    }
    String key = moduleName + ":" + op.name();
    Window w = WINDOWS.computeIfAbsent(key, k -> new Window());
    return w.record(key);
  }

  /**
   * Returns how much a denial is currently allowed to cost to describe.
   *
   * @return the active detail level
   */
  public static DenialDetail detail() {
    return detail;
  }

  /**
   * Changes the detail level at runtime.
   *
   * <p>This is the knob for an incident: a node drowning in denials can be moved to {@link
   * DenialDetail#NEVER} to stabilise it, and to {@link DenialDetail#ALWAYS} once a policy fix is
   * being verified -- without a restart, and without changing which operations are denied.
   *
   * @param level the level to use, or null to return to the configured default
   */
  public static void setDetail(DenialDetail level) {
    detail = (level == null) ? DenialDetail.parse(System.getProperty(PROP_DETAIL)) : level;
    LOG.info("Denial detail level set to {}", detail);
  }

  /** Clears all window state. Intended for tests and for policy reload. */
  public static void reset() {
    WINDOWS.clear();
    threshold = readThreshold();
    windowNanos = readWindowNanos();
    detail = DenialDetail.parse(System.getProperty(PROP_DETAIL));
  }

  /**
   * Returns the number of denials suppressed for a pair, for assertions and diagnostics.
   *
   * @param moduleName the caller's module
   * @param op the operation
   * @return suppressed count in the current window, or 0 if the pair is not tracked
   */
  public static long suppressedCount(String moduleName, Operation op) {
    Window w = WINDOWS.get(moduleName + ":" + op.name());
    return w == null ? 0L : w.suppressed.get();
  }

  private static int readThreshold() {
    return intProperty(PROP_THRESHOLD, DEFAULT_THRESHOLD);
  }

  private static long readWindowNanos() {
    int seconds = intProperty(PROP_WINDOW_SECONDS, (int) (DEFAULT_WINDOW_NANOS / 1_000_000_000L));
    return seconds <= 0 ? DEFAULT_WINDOW_NANOS : seconds * 1_000_000_000L;
  }

  private static int intProperty(String name, int fallback) {
    String raw = System.getProperty(name);
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    try {
      return Integer.parseInt(raw.trim());
    } catch (NumberFormatException e) {
      LOG.warn("Ignoring non-numeric {}={}, using {}", name, raw, fallback);
      return fallback;
    }
  }

  /** A sliding count for one (module, operation) pair. */
  private static final class Window {
    private final AtomicLong count = new AtomicLong();
    private final AtomicLong suppressed = new AtomicLong();
    private volatile long startedNanos = System.nanoTime();
    private volatile boolean tripped;

    boolean record(String key) {
      long now = System.nanoTime();
      long started = startedNanos;

      if (now - started > windowNanos) {
        // Window elapsed. Report what was hidden, then start clean.
        long hidden = suppressed.getAndSet(0L);
        count.set(0L);
        startedNanos = now;
        if (tripped) {
          tripped = false;
          LOG.warn(
              "Denial storm subsided for {}: {} denial(s) were enforced with detail suppressed;"
                  + " full detail resumes",
              key,
              hidden);
        }
      }

      if (count.incrementAndGet() <= threshold) {
        return true;
      }

      if (!tripped) {
        tripped = true;
        LOG.error(
            "Denial storm for {}: more than {} denials in {}s. Still denying every one of them,"
                + " but suppressing per-denial message, stack and log so enforcement cannot exhaust"
                + " the heap. Fix the missing entitlement; detail resumes when the rate falls.",
            key,
            threshold,
            windowNanos / 1_000_000_000L);
      }
      suppressed.incrementAndGet();
      return false;
    }
  }
}
