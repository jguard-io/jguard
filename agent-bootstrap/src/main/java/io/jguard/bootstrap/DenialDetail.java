/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

/**
 * How much a denial is allowed to cost to describe.
 *
 * <p>This is a diagnosability dial, not a security one. Every level denies exactly the same
 * operations and throws exactly the same exception type; they differ only in how much work is spent
 * explaining each denial -- message formatting, policy enumeration, stack capture and logging.
 *
 * <p>The distinction matters because describing a denial is far more expensive than making one. A
 * single missing entitlement on an initialisation path can be denied hundreds of thousands of times
 * per second, and at several kilobytes of description apiece that has exhausted the heap of the
 * very application jGuard was protecting.
 *
 * <p>Set with {@code -Djguard.denial.detail=<level>} and change at runtime through {@link
 * DenialStormGuard#setDetail(DenialDetail)}, so a node in trouble can be stabilised without a
 * restart and turned back up once a policy fix is being verified.
 */
public enum DenialDetail {

  /**
   * Never suppress. Every denial is described in full, however many there are.
   *
   * <p>For root-cause analysis: you are willing to pay the allocation to see every denial, on a
   * node you are already watching.
   */
  ALWAYS,

  /**
   * Describe denials in full until one {@code (module, operation)} pair starts storming, then
   * describe that pair cheaply until its rate falls.
   *
   * <p>The default, and the right setting for production: a normal burst keeps full detail, and a
   * runaway loop cannot turn enforcement into an out-of-memory error.
   */
  ADAPTIVE,

  /**
   * Always take the cheap path. Denials are counted and enforced but not individually described.
   *
   * <p>For a node under acute pressure, or a pair already diagnosed and merely waiting on a policy
   * release. {@link DenialCounters} still reports totals.
   */
  NEVER;

  /**
   * Parses a level name, case-insensitively, falling back to {@link #ADAPTIVE}.
   *
   * @param value the configured value, possibly null or blank
   * @return the parsed level, or {@link #ADAPTIVE} if absent or unrecognised
   */
  public static DenialDetail parse(String value) {
    if (value == null || value.isBlank()) {
      return ADAPTIVE;
    }
    try {
      return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
    } catch (IllegalArgumentException e) {
      return ADAPTIVE;
    }
  }
}
