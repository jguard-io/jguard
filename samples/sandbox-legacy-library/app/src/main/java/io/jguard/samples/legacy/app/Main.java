/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.legacy.app;

import io.jguard.samples.legacy.library.LegacyLibrary;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Demo application that uses a legacy (non-jGuard) library.
 *
 * <p>This demonstrates how jGuard handles third-party libraries that have no embedded policy:
 *
 * <ul>
 *   <li><b>Without external policy:</b> All sensitive operations from the library are BLOCKED
 *   <li><b>With external policy:</b> Deployer grants specific capabilities (allowlisting)
 * </ul>
 */
public class Main {

  public static void main(String[] args) throws IOException {
    System.out.println("=".repeat(70));
    System.out.println("  jGuard Legacy Library Demo");
    System.out.println("  Demonstrating: Restrictive by default for non-jGuard libraries");
    System.out.println("=".repeat(70));
    System.out.println();

    // Create a test config file
    Path configDir = Path.of("config");
    Path configFile = configDir.resolve("app.properties");
    if (!Files.exists(configDir)) {
      Files.createDirectories(configDir);
    }
    if (!Files.exists(configFile)) {
      Files.writeString(configFile, "app.name=LegacyDemo\napp.version=1.0\n");
    }

    System.out.println("Testing operations from legacy library (no jGuard policy):");
    System.out.println("-".repeat(70));
    System.out.println();

    // Test filesystem read from legacy library
    System.out.println("1. Filesystem Read (from legacy library):");
    String fsResult = LegacyLibrary.readConfig(configFile.toString());
    printResult("   fs.read", fsResult);
    System.out.println();

    // Test network access from legacy library
    System.out.println("2. Network Outbound (from legacy library):");
    String netResult = LegacyLibrary.fetchUrl("https://httpbin.org/get");
    printResult("   network.outbound", netResult);
    System.out.println();

    // Test system property read from legacy library
    System.out.println("3. System Property Read (from legacy library):");
    String propResult = LegacyLibrary.getProperty("java.version");
    printResult("   system.property.read", propResult);
    System.out.println();

    // Test thread creation from legacy library
    System.out.println("4. Thread Creation (from legacy library):");
    String threadResult = LegacyLibrary.createThread();
    printResult("   threads.create", threadResult);
    System.out.println();

    System.out.println("=".repeat(70));
    System.out.println("  Summary:");
    System.out.println("  - Legacy libraries have NO embedded jGuard policy");
    System.out.println("  - Without external policy: ALL operations BLOCKED (restrictive default)");
    System.out.println("  - With external policy: Deployer grants specific capabilities");
    System.out.println("=".repeat(70));
  }

  private static void printResult(String capability, String result) {
    String status = result.startsWith("SUCCESS") ? "ALLOWED" : "BLOCKED";
    String icon = result.startsWith("SUCCESS") ? "\u2713" : "\u2717";
    System.out.println("   " + capability + " ... " + icon + " " + status);
  }
}
