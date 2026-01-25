/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package io.jguard.samples.external.library;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * A simulated "overly permissive" third-party library.
 *
 * <p>This class demonstrates various operations that its embedded policy grants to the ENTIRE
 * module, even though only specific packages might need them:
 *
 * <ul>
 *   <li>{@code network.outbound} - The embedded policy grants this to the whole module
 *   <li>{@code threads.create} - The embedded policy grants this to the whole module
 *   <li>{@code native.load} - The embedded policy grants this to the whole module (dangerous!)
 *   <li>{@code fs.read} - Legitimately needed for config files
 *   <li>{@code process.exec} - v0.3: Grants process execution (dangerous!)
 *   <li>{@code fs.hardlink} - v0.3: Grants hard link creation (dangerous!)
 *   <li>{@code crypto.provider} - v0.3: Grants crypto provider modification (dangerous!)
 * </ul>
 *
 * <p>The external policy demo shows how a deployer can use {@code deny} statements to restrict
 * these overly broad grants at deployment time.
 */
public final class PermissiveLibrary {

  private PermissiveLibrary() {}

  // ========================================================================
  // Network Operations (embedded policy grants to entire module)
  // ========================================================================

  /**
   * Attempts to connect to a host. The embedded policy allows this for the
   * entire module, but external policy can restrict it.
   *
   * @param host the host to connect to
   * @param port the port to connect to
   * @return true if connection was allowed (may or may not succeed)
   */
  public static boolean tryConnect(String host, int port) {
    System.out.printf("  [Library] Attempting network connection to %s:%d%n", host, port);
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress(host, port), 1000);
      System.out.printf("  [Library] ✓ Connected to %s:%d%n", host, port);
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    } catch (IOException e) {
      // Connection allowed but failed (host unreachable, etc.)
      System.out.printf("  [Library] ✓ Connection allowed (failed: %s)%n", e.getMessage());
      return true;
    }
  }

  // ========================================================================
  // Thread Operations (embedded policy grants to entire module)
  // ========================================================================

  /**
   * Attempts to create a thread pool. The embedded policy allows this for the
   * entire module, but external policy can restrict it.
   *
   * @return true if thread creation was allowed
   */
  public static boolean tryCreateThreads() {
    System.out.println("  [Library] Attempting to create thread pool");
    try {
      ExecutorService executor = Executors.newFixedThreadPool(2);
      executor.submit(() -> System.out.println("  [Library]   Worker thread running"));
      executor.shutdown();
      executor.awaitTermination(1, TimeUnit.SECONDS);
      System.out.println("  [Library] ✓ Thread pool created successfully");
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return true;
    }
  }

  // ========================================================================
  // Native Load Operations (embedded policy grants to entire module - DANGEROUS!)
  // ========================================================================

  /**
   * Attempts to load a native library. The embedded policy allows this for the
   * entire module, which is a significant security risk. External policy should
   * deny this.
   *
   * @param libraryName the native library to load
   * @return true if native load was allowed (may or may not succeed)
   */
  public static boolean tryLoadNative(String libraryName) {
    System.out.printf("  [Library] Attempting to load native library: %s%n", libraryName);
    try {
      System.loadLibrary(libraryName);
      System.out.printf("  [Library] ✓ Native library loaded: %s%n", libraryName);
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    } catch (UnsatisfiedLinkError e) {
      // Load allowed but library not found
      System.out.printf("  [Library] ✓ Native load allowed (library not found: %s)%n", e.getMessage());
      return true;
    }
  }

  // ========================================================================
  // Filesystem Operations (legitimately needed)
  // ========================================================================

  /**
   * Reads a configuration file. This is a legitimate operation that the embedded
   * policy correctly grants.
   *
   * @param configPath path to the config file
   * @return the config content, or null if blocked/not found
   */
  public static String readConfig(Path configPath) {
    System.out.printf("  [Library] Reading config file: %s%n", configPath);
    try {
      String content = Files.readString(configPath);
      System.out.printf("  [Library] ✓ Config read successfully (%d chars)%n", content.length());
      return content;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return null;
    } catch (IOException e) {
      System.out.printf("  [Library] ✗ File not found: %s%n", e.getMessage());
      return null;
    }
  }

  // ========================================================================
  // System Property Operations (legitimately needed)
  // ========================================================================

  /**
   * Reads a system property. This is a legitimate operation.
   *
   * @param propertyName the property to read
   * @return the property value, or null if blocked/not set
   */
  public static String readProperty(String propertyName) {
    System.out.printf("  [Library] Reading system property: %s%n", propertyName);
    try {
      String value = System.getProperty(propertyName);
      if (value != null) {
        System.out.printf("  [Library] ✓ Property value: %s%n", value);
      } else {
        System.out.printf("  [Library] ✓ Property not set%n");
      }
      return value;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return null;
    }
  }

  // ========================================================================
  // v0.3: Process Execution (DANGEROUS - embedded policy grants this!)
  // ========================================================================

  /**
   * Attempts to execute a command. The embedded policy allows this for the entire module, which is
   * a significant security risk. External policy should deny this.
   *
   * @param command the command to execute
   * @return true if process execution was allowed
   */
  public static boolean tryExecuteProcess(String command) {
    System.out.printf("  [Library] Attempting to execute: %s%n", command);
    try {
      ProcessBuilder pb = new ProcessBuilder(command.split("\\s+"));
      pb.redirectErrorStream(true);
      Process process = pb.start();

      String output;
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        output = reader.lines().collect(Collectors.joining("\n"));
      }

      int exitCode = process.waitFor();
      System.out.printf("  [Library] ✓ Process executed (exit %d): %s%n", exitCode, output);
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    } catch (Exception e) {
      System.out.printf("  [Library] ✓ Execution allowed (failed: %s)%n", e.getMessage());
      return true;
    }
  }

  // ========================================================================
  // v0.3: Hard Link Creation (DANGEROUS - embedded policy grants this!)
  // ========================================================================

  /**
   * Attempts to create a hard link. The embedded policy allows this for the entire module, which
   * could be used to escape filesystem boundaries. External policy should deny this.
   *
   * @param source the source file
   * @param link the link path
   * @return true if hard link creation was allowed
   */
  public static boolean tryCreateHardLink(Path source, Path link) {
    System.out.printf("  [Library] Attempting to create hard link: %s -> %s%n", link, source);
    try {
      Files.deleteIfExists(link);
      Files.createLink(link, source);
      System.out.printf("  [Library] ✓ Hard link created: %s%n", link);
      Files.deleteIfExists(link);
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    } catch (IOException e) {
      System.out.printf("  [Library] ✓ Creation allowed (failed: %s)%n", e.getMessage());
      return true;
    }
  }

  // ========================================================================
  // v0.3: Crypto Provider (DANGEROUS - embedded policy grants this!)
  // ========================================================================

  /**
   * Attempts to add a crypto provider. The embedded policy allows this for the entire module, which
   * could be used to install malicious crypto. External policy should deny this.
   *
   * @return true if crypto provider modification was allowed
   */
  public static boolean tryAddCryptoProvider() {
    System.out.println("  [Library] Attempting to add crypto provider");
    try {
      Provider testProvider =
          new Provider("MaliciousProvider", "1.0", "Potentially malicious provider") {
            private static final long serialVersionUID = 1L;
          };
      int position = Security.addProvider(testProvider);
      System.out.printf("  [Library] ✓ Provider added at position %d%n", position);
      Security.removeProvider("MaliciousProvider");
      return true;
    } catch (SecurityException e) {
      System.out.printf("  [Library] ✗ BLOCKED by jGuard: %s%n", e.getMessage());
      return false;
    }
  }
}
