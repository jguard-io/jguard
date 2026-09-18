/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

/**
 * Enforcement mode controlling how jGuard handles policy decisions and errors.
 *
 * <p>The enforcement mode determines the agent's behavior in two scenarios:
 *
 * <ol>
 *   <li>When a capability check fails (not entitled)
 *   <li>When an error occurs during enforcement (agent bug, missing policy, etc.)
 * </ol>
 *
 * <h2>Mode Comparison</h2>
 *
 * <ul>
 *   <li><b>STRICT</b>: Block denied access, block on errors (Production)
 *   <li><b>PERMISSIVE</b>: Block denied access, allow on errors (Migration)
 *   <li><b>AUDIT</b>: Log only, never block (Testing)
 * </ul>
 */
public enum EnforcementMode {

  /**
   * Strict enforcement: fail closed on all decisions and errors.
   *
   * <p>This is the recommended mode for production. Operations are blocked if:
   *
   * <ul>
   *   <li>The caller is not entitled to the capability
   *   <li>Any error occurs during enforcement
   *   <li>The caller cannot be attributed ("unknown" caller)
   * </ul>
   */
  STRICT,

  /**
   * Permissive enforcement: fail open on errors, closed on policy denials.
   *
   * <p>This mode is designed for migration scenarios where:
   *
   * <ul>
   *   <li>Known policy violations should still be blocked
   *   <li>Agent errors or edge cases should not break the application
   *   <li>Logs can be reviewed to identify issues before switching to STRICT
   * </ul>
   */
  PERMISSIVE,

  /**
   * Audit mode: decide everything, block nothing.
   *
   * <p>This mode is for testing and policy development:
   *
   * <ul>
   *   <li>Every denial is logged, so a policy can be completed from a running application
   *   <li>No operations are blocked
   *   <li>Useful for discovering what entitlements an application needs
   * </ul>
   *
   * <p>Allowed operations are <em>not</em> logged unless asked for. They used to be, and the cost
   * is not what it sounds like: jGuard intercepts every property read, file open and socket connect
   * the application makes, so logging the allowed ones is a line per intercepted operation, at
   * INFO, for as long as the process runs. On a production node that measured around forty lines a
   * second -- and what it reports is the entitlements the policy already grants, which is the half
   * nobody is hunting. The denials are the signal, and audit mode exists to find those.
   *
   * <p>Set {@code jguard.log.allowed=true} to turn it on deliberately, or toggle it on a running
   * JVM through the {@code io.jguard:type=Control} MBean -- which is the better tool anyway, since
   * the firehose is only wanted for the minute someone is actually reading it.
   */
  AUDIT;

  /**
   * Parses an enforcement mode from a string, case-insensitively.
   *
   * @param value the string value (e.g., "strict", "PERMISSIVE", "Audit")
   * @return the corresponding enforcement mode
   * @throws IllegalArgumentException if the value doesn't match any mode
   */
  public static EnforcementMode parse(String value) {
    if (value == null || value.isBlank()) {
      return STRICT; // Default
    }
    try {
      return valueOf(value.toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Invalid enforcement mode: '" + value + "'. Valid values are: strict, permissive, audit");
    }
  }

  /**
   * Returns true if this mode blocks on policy violations (not entitled).
   *
   * @return true if denied access should throw an exception
   */
  public boolean blocksOnDenied() {
    return this != AUDIT;
  }

  /**
   * Returns true if this mode blocks on internal errors.
   *
   * @return true if enforcement errors should throw an exception
   */
  public boolean blocksOnError() {
    return this == STRICT;
  }

  /**
   * Returns true if this mode logs allowed operations by default.
   *
   * <p>No mode does. AUDIT used to, on the reasoning that an audit should record every decision,
   * and that does not survive contact with an intercepted JVM: an allowed operation is every
   * property read, file open and socket connect the application performs, so the log becomes a line
   * per operation at INFO and the interesting half -- the denials, which AUDIT still logs in full
   * -- is buried in it. Turning the firehose on is now a deliberate act: {@code
   * jguard.log.allowed=true}, or the {@code io.jguard:type=Control} MBean at runtime.
   *
   * <p>Kept as a per-mode decision rather than deleted so a future mode can answer differently
   * without reopening every call site.
   *
   * @return true if allowed operations should be logged when not set explicitly
   */
  public boolean logsAllowed() {
    return false;
  }
}
