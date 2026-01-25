/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package io.jguard.samples.external.app;

import io.jguard.samples.external.library.PermissiveLibrary;

import java.nio.file.Path;

/**
 * Demonstrates external policy grant/deny functionality.
 *
 * <p>This application uses a "third-party" library that has overly permissive
 * embedded policies. External policies can restrict those permissions at
 * deployment time without modifying the library.
 *
 * <h2>Running the Demo</h2>
 * <pre>
 * # Without jGuard (baseline - everything allowed)
 * ./gradlew :app:runWithoutAgent
 *
 * # With jGuard + external policies (dangerous operations blocked)
 * ./gradlew :app:runWithAgent
 * </pre>
 */
public final class Main {

  public static void main(String[] args) {
    System.out.println("=".repeat(70));
    System.out.println("External Policy Grant/Deny Demo");
    System.out.println("=".repeat(70));
    System.out.println();

    // ====================================================================
    // Test 1: Network Operations
    // ====================================================================
    section("Network Operations");
    System.out.println("The library's embedded policy grants network.outbound to the ENTIRE module.");
    System.out.println("External policy can DENY this to prevent network access.");
    System.out.println();

    // Try connecting to a public host
    PermissiveLibrary.tryConnect("httpbin.org", 443);
    System.out.println();

    // Try connecting to localhost (potentially more sensitive)
    PermissiveLibrary.tryConnect("localhost", 8080);
    System.out.println();

    // ====================================================================
    // Test 2: Thread Operations
    // ====================================================================
    section("Thread Operations");
    System.out.println("The library's embedded policy grants threads.create to the ENTIRE module.");
    System.out.println("External policy can DENY this to prevent thread creation.");
    System.out.println();

    PermissiveLibrary.tryCreateThreads();
    System.out.println();

    // ====================================================================
    // Test 3: Native Load Operations
    // ====================================================================
    section("Native Load Operations (DANGEROUS!)");
    System.out.println("The library's embedded policy grants native.load to the ENTIRE module.");
    System.out.println("This is a significant security risk - external policy SHOULD deny this!");
    System.out.println();

    PermissiveLibrary.tryLoadNative("nonexistent");
    System.out.println();

    // ====================================================================
    // Test 4: Filesystem Operations (Legitimate)
    // ====================================================================
    section("Filesystem Operations (Legitimate)");
    System.out.println("The library legitimately needs fs.read for config files.");
    System.out.println("External policy should NOT deny this.");
    System.out.println();

    // Try to read a config file (may not exist, but tests permission)
    PermissiveLibrary.readConfig(Path.of("config", "app.properties"));
    System.out.println();

    // ====================================================================
    // Test 5: System Property Operations (Legitimate)
    // ====================================================================
    section("System Property Operations (Legitimate)");
    System.out.println("The library legitimately needs system.property.read.");
    System.out.println("External policy should NOT deny this.");
    System.out.println();

    PermissiveLibrary.readProperty("java.version");
    PermissiveLibrary.readProperty("user.home");
    System.out.println();

    // ====================================================================
    // v0.3 Test 6: Process Execution (DANGEROUS!)
    // ====================================================================
    section("v0.3: Process Execution (DANGEROUS!)");
    System.out.println("The library's embedded policy grants process.exec to the ENTIRE module.");
    System.out.println("This could allow shell escapes - external policy SHOULD deny this!");
    System.out.println();

    PermissiveLibrary.tryExecuteProcess("/bin/echo Hello from library");
    System.out.println();

    // ====================================================================
    // v0.3 Test 7: Hard Link Creation (DANGEROUS!)
    // ====================================================================
    section("v0.3: Hard Link Creation (DANGEROUS!)");
    System.out.println("The library's embedded policy grants fs.hardlink to the ENTIRE module.");
    System.out.println("This could escape filesystem boundaries - external policy SHOULD deny this!");
    System.out.println();

    // Create a temp source file for the test
    try {
      Path tempFile = java.nio.file.Files.createTempFile("jguard-test", ".txt");
      java.nio.file.Files.writeString(tempFile, "Test content");
      Path linkPath = tempFile.resolveSibling("jguard-test-link.txt");
      PermissiveLibrary.tryCreateHardLink(tempFile, linkPath);
      java.nio.file.Files.deleteIfExists(tempFile);
    } catch (Exception e) {
      System.out.println("  [App] Could not set up test: " + e.getMessage());
    }
    System.out.println();

    // ====================================================================
    // v0.3 Test 8: Crypto Provider (DANGEROUS!)
    // ====================================================================
    section("v0.3: Crypto Provider Modification (DANGEROUS!)");
    System.out.println("The library's embedded policy grants crypto.provider to the ENTIRE module.");
    System.out.println("This could install malicious crypto - external policy SHOULD deny this!");
    System.out.println();

    PermissiveLibrary.tryAddCryptoProvider();
    System.out.println();

    // ====================================================================
    // Summary
    // ====================================================================
    section("Summary");
    System.out.println("Check the output above to see which operations were allowed/blocked.");
    System.out.println();
    System.out.println("With external policies enabled:");
    System.out.println("  - native.load should be BLOCKED (external policy denies it)");
    System.out.println("  - threads.create should be BLOCKED (external policy denies it)");
    System.out.println("  - process.exec should be BLOCKED (v0.3 - external policy denies it)");
    System.out.println("  - fs.hardlink should be BLOCKED (v0.3 - external policy denies it)");
    System.out.println("  - crypto.provider should be BLOCKED (v0.3 - external policy denies it)");
    System.out.println("  - Legitimate operations (fs.read, property.read) should be allowed");
    System.out.println();
    System.out.println("=".repeat(70));
  }

  private static void section(String title) {
    System.out.println("-".repeat(70));
    System.out.printf(">>> %s%n", title);
    System.out.println("-".repeat(70));
  }
}
