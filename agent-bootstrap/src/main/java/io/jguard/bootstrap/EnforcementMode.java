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
   * Audit mode: log all decisions but never block.
   *
   * <p>This mode is for testing and policy development:
   *
   * <ul>
   *   <li>All capability checks are logged (allowed and denied)
   *   <li>No operations are blocked
   *   <li>Useful for discovering what entitlements an application needs
   * </ul>
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
   * Returns true if this mode logs allowed operations.
   *
   * @return true if allowed operations should be logged
   */
  public boolean logsAllowed() {
    return this == AUDIT;
  }
}
