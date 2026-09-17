/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

/**
 * The denial returned when a storming pair is being denied cheaply.
 *
 * <p>Refusing an operation costs almost nothing. <em>Describing</em> the refusal is what costs: a
 * formatted message naming the module, the capability and the argument, and then a {@link
 * SecurityException} whose construction captures the whole stack. On a pair being denied hundreds
 * of thousands of times a second that is kilobytes per denial, and it has exhausted the heap of the
 * application the agent was protecting.
 *
 * <p>So past a threshold {@link DenialStormGuard} tells the enforcer to stop describing, and this
 * is what it returns instead: one shared, immutable instance that carries no stack.
 *
 * <h2>This is still a denial</h2>
 *
 * <p>It is a {@link SecurityException}, it is thrown by the same code path, and it stops the same
 * operations. Nothing about the decision changes -- only how much is spent explaining it. A caller
 * catching {@code SecurityException} cannot tell the difference, which is the point: suppression
 * must not be observable as permission.
 *
 * <h2>Why it has no stack</h2>
 *
 * <p>{@code fillInStackTrace} is overridden to do nothing, which is what makes a shared instance
 * safe as well as cheap: with no stack there is nothing thread-specific to race over, and no
 * misleading trace from whichever thread happened to construct it first. The cost is that a
 * suppressed denial cannot be traced to its call site -- deliberately, and recoverably: set {@code
 * -Djguard.denial.detail=always}, or call {@link DenialStormGuard#setDetail}, and the next denial
 * carries a full message and stack again without restarting anything.
 */
public final class SuppressedDenial extends SecurityException {

  private static final long serialVersionUID = 1L;

  /** The single instance returned for every suppressed denial. */
  public static final SuppressedDenial INSTANCE = new SuppressedDenial();

  private SuppressedDenial() {
    super(
        "jGuard: access denied. Per-denial detail is suppressed because this module and operation"
            + " are being denied faster than they can be described; the operation is still denied."
            + " Set -Djguard.denial.detail=always (or DenialStormGuard.setDetail(ALWAYS)) to restore"
            + " the full message and stack.");
  }

  /**
   * Does not capture a stack.
   *
   * @return this exception, uninitialised
   */
  @Override
  public synchronized Throwable fillInStackTrace() {
    return this;
  }
}
