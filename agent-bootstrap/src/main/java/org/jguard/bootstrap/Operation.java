/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

/**
 * Operations that require capability enforcement.
 *
 * <p>Each operation corresponds to a capability in the policy DSL. The {@link #capabilityName()}
 * maps to the policy capability, and {@link #category()} determines the matching logic.
 *
 * <h2>Extending jGuard</h2>
 *
 * <p>To add a new capability:
 *
 * <ol>
 *   <li>Add an enum entry here with capability name and category
 *   <li>Add entry point in {@code BootstrapEnforcer.onXxx()}
 *   <li>Add ByteBuddy advice calling the entry point
 *   <li>Wire the advice in {@code JGuardAgent}
 * </ol>
 *
 * <p>If using an existing category, no changes to PolicyEnforcer are needed.
 */
public enum Operation {

  /**
   * Filesystem read operation.
   *
   * <p>Arguments: {@code arg0} = Path, {@code arg1} = 0
   */
  FS_READ("fs.read", Category.FILESYSTEM),

  /**
   * Filesystem write operation.
   *
   * <p>Arguments: {@code arg0} = Path, {@code arg1} = 0
   */
  FS_WRITE("fs.write", Category.FILESYSTEM),

  /**
   * Network outbound connection.
   *
   * <p>Arguments: {@code arg0} = String host, {@code arg1} = port
   */
  NET_CONNECT("network.outbound", Category.HOST_PORT),

  /**
   * Network listen (server socket bind).
   *
   * <p>Arguments: {@code arg0} = null, {@code arg1} = port (0 = ephemeral)
   */
  NET_LISTEN("network.listen", Category.PORT),

  /**
   * Thread creation.
   *
   * <p>Arguments: {@code arg0} = thread name (for logging), {@code arg1} = 0
   */
  THREAD_CREATE("threads.create", Category.SIMPLE),

  /**
   * Native library loading.
   *
   * <p>Arguments: {@code arg0} = library name, {@code arg1} = 0
   */
  NATIVE_LOAD("native.load", Category.TARGET_PATTERN);

  /**
   * Categories determine matching logic in PolicyEnforcer.
   *
   * <p>Adding a new capability with an existing category requires no PolicyEnforcer changes.
   */
  public enum Category {
    /**
     * Filesystem operations with root + glob matching.
     *
     * <p>Policy args: {@code (root, glob)}
     */
    FILESYSTEM,

    /**
     * Simple capabilities with no argument matching.
     *
     * <p>If entitled, operation is allowed regardless of arguments.
     */
    SIMPLE,

    /**
     * Port-based capabilities with optional port or port-range restriction.
     *
     * <p>Policy args: none (any port), {@code (port)} for specific port, or {@code ("start-end")}
     * for port range.
     */
    PORT,

    /**
     * Host and port filtering capabilities.
     *
     * <p>Policy args: none (any host/port), {@code (hostPattern)} for host filtering, {@code
     * (hostPattern, port)} or {@code (hostPattern, "start-end")} for both.
     *
     * <p>Host patterns support:
     *
     * <ul>
     *   <li>{@code *} - any single DNS segment
     *   <li>{@code **} - one or more DNS segments
     *   <li>Literal segments for exact matching
     * </ul>
     */
    HOST_PORT,

    /**
     * Target pattern capabilities with optional pattern matching.
     *
     * <p>Policy args: none (any target) or {@code (pattern)} for specific targets. Use for
     * reflection, native loading, process execution, etc.
     */
    TARGET_PATTERN
  }

  private final String capabilityName;
  private final Category category;

  Operation(String capabilityName, Category category) {
    this.capabilityName = capabilityName;
    this.category = category;
  }

  /** Returns the capability name used in policy files (e.g., "fs.read", "network.outbound"). */
  public String capabilityName() {
    return capabilityName;
  }

  /** Returns the category that determines matching logic. */
  public Category category() {
    return category;
  }
}
