/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.java;

import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import java.util.List;

/**
 * Factory methods for creating capability grants.
 *
 * <p>This class provides type-safe, IDE-friendly methods for defining capabilities in Java code.
 * Use with static imports for a clean DSL:
 *
 * <pre>{@code
 * import static io.jguard.policy.java.Capabilities.*;
 *
 * grant(module(), fsRead("/data", "*.json"));
 * grant(pkg("com.example.net"), networkOutbound());
 * }</pre>
 *
 * <p>All capability methods validate arguments at construction time and produce the same {@link
 * CapabilityGrant} objects as the policy compiler.
 */
public final class Capabilities {

  private Capabilities() {
    // Static factory class
  }

  // ===== Filesystem Capabilities =====

  /**
   * Creates a filesystem read capability.
   *
   * @param root the root directory path
   * @param glob the glob pattern for matching files
   * @return the capability grant
   */
  public static CapabilityGrant fsRead(String root, String glob) {
    validateNotNull(root, "root");
    validateNotNull(glob, "glob");
    return CapabilityGrant.of(
        "fs.read",
        List.of(new CapabilityArgument.StringArg(root), new CapabilityArgument.StringArg(glob)));
  }

  /**
   * Creates a filesystem write capability.
   *
   * @param root the root directory path
   * @param glob the glob pattern for matching files
   * @return the capability grant
   */
  public static CapabilityGrant fsWrite(String root, String glob) {
    validateNotNull(root, "root");
    validateNotNull(glob, "glob");
    return CapabilityGrant.of(
        "fs.write",
        List.of(new CapabilityArgument.StringArg(root), new CapabilityArgument.StringArg(glob)));
  }

  /**
   * Creates a filesystem hard link capability.
   *
   * <p>Hard link creation allows creating a new directory entry pointing to an existing file. This
   * requires special permission because it can bypass filesystem boundaries.
   *
   * @param root the root directory path for link destinations
   * @param glob the glob pattern for matching link paths
   * @return the capability grant
   */
  public static CapabilityGrant fsHardlink(String root, String glob) {
    validateNotNull(root, "root");
    validateNotNull(glob, "glob");
    return CapabilityGrant.of(
        "fs.hardlink",
        List.of(new CapabilityArgument.StringArg(root), new CapabilityArgument.StringArg(glob)));
  }

  // ===== Network Capabilities =====

  /**
   * Creates a network outbound capability.
   *
   * @return the capability grant
   */
  public static CapabilityGrant networkOutbound() {
    return CapabilityGrant.of("network.outbound");
  }

  /**
   * Creates a network listen capability.
   *
   * @param port the port to listen on
   * @return the capability grant
   */
  public static CapabilityGrant networkListen(int port) {
    if (port < 0 || port > 65535) {
      throw new IllegalArgumentException("Port must be between 0 and 65535: " + port);
    }
    return CapabilityGrant.of("network.listen", List.of(new CapabilityArgument.IntegerArg(port)));
  }

  // ===== Thread Capabilities =====

  /**
   * Creates a thread creation capability.
   *
   * @return the capability grant
   */
  public static CapabilityGrant threadsCreate() {
    return CapabilityGrant.of("threads.create");
  }

  // ===== Native Capabilities =====

  /**
   * Creates a native library load capability.
   *
   * @return the capability grant
   */
  public static CapabilityGrant nativeLoad() {
    return CapabilityGrant.of("native.load");
  }

  // ===== Process Capabilities =====

  /**
   * Creates a process execution capability allowing any command.
   *
   * <p><b>Security Warning:</b> This grants unrestricted process execution. Consider using {@link
   * #processExec(String)} with a pattern to limit allowed commands.
   *
   * @return the capability grant
   */
  public static CapabilityGrant processExec() {
    return CapabilityGrant.of("process.exec");
  }

  /**
   * Creates a process execution capability with a command pattern.
   *
   * <p>The pattern matches the first element of the command (the executable path or name).
   *
   * @param pattern the command pattern (e.g., "/usr/bin/java", "/opt/app/bin/*")
   * @return the capability grant
   */
  public static CapabilityGrant processExec(String pattern) {
    validateNotNull(pattern, "pattern");
    return CapabilityGrant.of("process.exec", List.of(new CapabilityArgument.StringArg(pattern)));
  }

  // ===== Crypto Capabilities =====

  /**
   * Creates a crypto provider capability.
   *
   * <p>This grants permission to modify Java crypto providers (add, remove, configure). Required
   * for installing custom cryptographic providers like BouncyCastle.
   *
   * @return the capability grant
   */
  public static CapabilityGrant cryptoProvider() {
    return CapabilityGrant.of("crypto.provider");
  }

  // ===== Validation =====

  private static void validateNotNull(Object value, String name) {
    if (value == null) {
      throw new IllegalArgumentException(name + " cannot be null");
    }
  }
}
