/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jguard.core.JGuard;

/**
 * Demonstrates jGuard capability-based security enforcement.
 *
 * <p>This sample shows operations that require entitlements defined in {@code
 * module-info.jguard}:
 *
 * <ul>
 *   <li>fs.read("src", "**\/*") - filesystem read access to source directory
 *   <li>fs.write("build/test-output", "**") - filesystem write access to test output directory
 * </ul>
 *
 * <h2>Running without the agent (no enforcement):</h2>
 *
 * <pre>{@code
 * ./gradlew :samples:sandbox-demo:run
 * }</pre>
 *
 * <p>All operations succeed because there's no enforcement.
 *
 * <h2>Running with the agent (enforcement enabled):</h2>
 *
 * <pre>{@code
 * ./gradlew :samples:sandbox-demo:runWithAgent
 * }</pre>
 *
 * <p>Entitled operations succeed, non-entitled operations are blocked.
 */
public final class Main {

  public static void main(String[] args) {
    System.out.println("jGuard Sandbox Demo");
    System.out.println("===================");
    System.out.println("Runtime version: " + JGuard.version());
    System.out.println();

    // === READ TESTS ===
    System.out.println("--- READ TESTS ---");
    System.out.println();

    // Test 1: Access to project source using Files API (ENTITLED)
    demonstrateEntitledAccess();

    // Test 2: Access to project source using FileInputStream (ENTITLED)
    demonstrateEntitledFileInputStreamAccess();

    // Test 3: Access to user home using Files API (NOT ENTITLED)
    demonstrateUnentitledAccess();

    // Test 4: Access to user home using FileInputStream (NOT ENTITLED)
    demonstrateUnentitledFileInputStreamAccess();

    // === WRITE TESTS ===
    System.out.println("--- WRITE TESTS ---");
    System.out.println();

    // Test 5: Write to build output directory (ENTITLED)
    demonstrateEntitledWriteAccess();

    // Test 6: Write to build output using FileOutputStream (ENTITLED)
    demonstrateEntitledFileOutputStreamAccess();

    // Test 7: Write to /tmp directory (NOT ENTITLED)
    demonstrateUnentitledWriteAccess();

    // Test 8: Write to /tmp using FileOutputStream (NOT ENTITLED)
    demonstrateUnentitledFileOutputStreamAccess();
  }

  /**
   * Demonstrates filesystem read access to the project's source directory.
   *
   * <p>This operation IS entitled by the policy.
   */
  private static void demonstrateEntitledAccess() {
    // Read this class's own source file (entitled by policy)
    String srcPath = "src/main/java/org/jguard/samples/sandbox/Main.java";
    System.out.println("[ENTITLED] fs.read(\"src\", \"**/*\")");
    System.out.println("  Attempting to read own source file...");

    Path sourceFile = Path.of(srcPath);
    try {
      String content = Files.readString(sourceFile);
      System.out.println("  SUCCESS: Read " + content.length() + " bytes from " + sourceFile.getFileName());
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates FileInputStream access to entitled paths.
   *
   * <p>This tests that the legacy FileInputStream API is also instrumented.
   */
  private static void demonstrateEntitledFileInputStreamAccess() {
    String srcPath = "src/main/java/org/jguard/samples/sandbox/Main.java";
    System.out.println("[ENTITLED via FileInputStream]");
    System.out.println("  Attempting to read own source file with FileInputStream...");

    File sourceFile = new File(srcPath);
    try (FileInputStream fis = new FileInputStream(sourceFile)) {
      byte[] buffer = new byte[100];
      int bytesRead = fis.read(buffer);
      System.out.println("  SUCCESS: Read " + bytesRead + " bytes via FileInputStream");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates filesystem read access to user home directory.
   *
   * <p>This operation is NOT entitled - it should be blocked when the agent is active.
   */
  private static void demonstrateUnentitledAccess() {
    String userHome = System.getProperty("user.home");
    System.out.println("[NOT ENTITLED] Attempting to list " + userHome + "...");

    Path homeDir = Path.of(userHome);
    try {
      long fileCount = Files.list(homeDir).count();
      System.out.println("  SUCCESS: Found " + fileCount + " entries");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates FileInputStream access to non-entitled paths.
   *
   * <p>This tests that the legacy FileInputStream API is also blocked for non-entitled paths.
   */
  private static void demonstrateUnentitledFileInputStreamAccess() {
    String userHome = System.getProperty("user.home");
    File profileFile = new File(userHome, ".zprofile");
    System.out.println("[NOT ENTITLED via FileInputStream]");
    System.out.println("  Attempting to read " + profileFile + "...");

    try (FileInputStream fis = new FileInputStream(profileFile)) {
      byte[] buffer = new byte[100];
      int bytesRead = fis.read(buffer);
      System.out.println("  SUCCESS: Read " + bytesRead + " bytes via FileInputStream");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (IOException e) {
      // File not found is also expected if file doesn't exist
      if (e.getMessage() != null && e.getMessage().contains("No such file")) {
        System.out.println("  FILE NOT FOUND (try a different file)");
      } else {
        System.out.println("  ERROR: " + e.getMessage());
      }
    }

    System.out.println();
  }

  /**
   * Demonstrates filesystem write access to the build output directory.
   *
   * <p>This operation IS entitled by the policy.
   */
  private static void demonstrateEntitledWriteAccess() {
    Path outputDir = Path.of("build/test-output");
    Path testFile = outputDir.resolve("test-file.txt");
    System.out.println("[ENTITLED] fs.write(\"build/test-output\", \"**\")");
    System.out.println("  Attempting to write to " + testFile + "...");

    try {
      // Ensure directory exists
      Files.createDirectories(outputDir);
      // Write a test file
      Files.writeString(testFile, "Hello from jGuard sandbox demo!\n");
      System.out.println("  SUCCESS: Wrote file to " + testFile);
      // Clean up
      Files.deleteIfExists(testFile);
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates FileOutputStream access to entitled paths.
   *
   * <p>This tests that the legacy FileOutputStream API is also instrumented.
   */
  private static void demonstrateEntitledFileOutputStreamAccess() {
    Path outputDir = Path.of("build/test-output");
    File testFile = new File(outputDir.toFile(), "test-file-fos.txt");
    System.out.println("[ENTITLED via FileOutputStream]");
    System.out.println("  Attempting to write to " + testFile + "...");

    try {
      // Ensure directory exists
      Files.createDirectories(outputDir);
      try (FileOutputStream fos = new FileOutputStream(testFile)) {
        fos.write("Hello from FileOutputStream!\n".getBytes());
      }
      System.out.println("  SUCCESS: Wrote file via FileOutputStream");
      // Clean up
      testFile.delete();
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates filesystem write access to /tmp directory.
   *
   * <p>This operation is NOT entitled - it should be blocked when the agent is active.
   */
  private static void demonstrateUnentitledWriteAccess() {
    Path tmpDir = Path.of(System.getProperty("java.io.tmpdir"));
    Path testFile = tmpDir.resolve("jguard-unentitled-test.txt");
    System.out.println("[NOT ENTITLED] Attempting to write to " + testFile + "...");

    try {
      Files.writeString(testFile, "This should be blocked!\n");
      System.out.println("  SUCCESS: Wrote file (unexpected!)");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
      // Clean up
      Files.deleteIfExists(testFile);
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  /**
   * Demonstrates FileOutputStream access to non-entitled paths.
   *
   * <p>This tests that the legacy FileOutputStream API is also blocked for non-entitled paths.
   */
  private static void demonstrateUnentitledFileOutputStreamAccess() {
    Path tmpDir = Path.of(System.getProperty("java.io.tmpdir"));
    File testFile = new File(tmpDir.toFile(), "jguard-unentitled-fos-test.txt");
    System.out.println("[NOT ENTITLED via FileOutputStream]");
    System.out.println("  Attempting to write to " + testFile + "...");

    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write("This should be blocked!\n".getBytes());
      System.out.println("  SUCCESS: Wrote file via FileOutputStream (unexpected!)");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
      // Clean up
      testFile.delete();
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (IOException e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }
}
