/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

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
  NATIVE_LOAD("native.load", Category.TARGET_PATTERN),

  /**
   * Environment variable read.
   *
   * <p>Arguments: {@code arg0} = env var name (null for bulk getenv()), {@code arg1} = 0
   */
  ENV_READ("env.read", Category.TARGET_PATTERN),

  /**
   * System property read.
   *
   * <p>Arguments: {@code arg0} = property key (null for bulk getProperties()), {@code arg1} = 0
   */
  PROP_READ("system.property.read", Category.TARGET_PATTERN),

  /**
   * System property write.
   *
   * <p>Arguments: {@code arg0} = property key (null for bulk setProperties()), {@code arg1} = 0
   */
  PROP_WRITE("system.property.write", Category.TARGET_PATTERN),

  /**
   * Process execution.
   *
   * <p>Arguments: {@code arg0} = command/path, {@code arg1} = 0
   *
   * <p>Guards: {@code Runtime.exec()}, {@code ProcessBuilder.start()}
   */
  PROCESS_EXEC("process.exec", Category.TARGET_PATTERN),

  /**
   * Hard link creation.
   *
   * <p>Arguments: {@code arg0} = link Path, {@code arg1} = 0
   *
   * <p>Guards: {@code Files.createLink()}. Note: caller also needs {@code fs.read} on the existing
   * file and {@code fs.write} on the link parent directory.
   */
  FS_HARDLINK("fs.hardlink", Category.FILESYSTEM),

  /**
   * Crypto provider access.
   *
   * <p>Arguments: {@code arg0} = null, {@code arg1} = 0
   *
   * <p>Guards: {@code Security.addProvider()}, {@code Security.insertProviderAt()}, {@code
   * Security.removeProvider()}, {@code Security.setProperty()}
   */
  CRYPTO_PROVIDER("crypto.provider", Category.SIMPLE);

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
     * <p>Policy args: none (any target) or {@code (pattern)} for specific targets. Use for native
     * loading, environment variable access, system property access, etc.
     *
     * <p>When {@code arg0} is null, it indicates a bulk access (e.g., {@code System.getenv()},
     * {@code System.getProperties()}). Bulk access requires no-arg entitlement or {@code "*"}
     * pattern.
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
