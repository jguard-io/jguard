/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.multimodule.app;

import io.jguard.samples.multimodule.core.ConfigReader;
import io.jguard.samples.multimodule.network.SimpleHttpClient;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Multi-module sandbox demo application.
 *
 * <p>This demonstrates jGuard's multi-module support where:
 *
 * <ul>
 *   <li>Each module has its own policy (module-info.jguard)
 *   <li>Each module can only use its own entitlements
 *   <li>Cross-module access is properly isolated
 * </ul>
 *
 * <p>The app module has minimal entitlements. It must delegate:
 *
 * <ul>
 *   <li>File reading to the core module (which has fs.read)
 *   <li>Network access to the network module (which has network.outbound)
 * </ul>
 */
public class Main {

  public static void main(String[] args) {
    System.out.println("jGuard Multi-Module Demo");
    System.out.println("========================");
    System.out.println();
    System.out.println("This demo shows how jGuard enforces module-level security.");
    System.out.println("Each module has its own policy - cross-module access is blocked.");
    System.out.println();

    // Test 1: App module entitlements (should work)
    testAppEntitlements();

    // Test 2: Delegated file reading via core module
    testDelegatedFileReading();

    // Test 3: Direct file reading from app module (should be blocked)
    testDirectFileReading();

    // Test 4: Delegated network access via network module
    testDelegatedNetworkAccess();

    // Test 5: Direct network access from app module (should be blocked)
    testDirectNetworkAccess();

    System.out.println();
    System.out.println("Demo complete!");
  }

  private static void testAppEntitlements() {
    System.out.println("--- TEST 1: App Module Entitlements ---");
    System.out.println();

    // env.read is entitled for HOME and USER
    System.out.println("[ENTITLED] env.read(\"HOME\")");
    try {
      String home = System.getenv("HOME");
      System.out.println("  SUCCESS: HOME = " + home);
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    }

    System.out.println();
    System.out.println("[NOT ENTITLED] env.read(\"PATH\")");
    try {
      String path = System.getenv("PATH");
      if (path != null) {
        System.out.println("  SUCCESS (unexpected): PATH = " + path.substring(0, Math.min(50, path.length())) + "...");
        System.out.println("  (This should be BLOCKED when running with the agent!)");
      }
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    }

    System.out.println();
  }

  private static void testDelegatedFileReading() {
    System.out.println("--- TEST 2: Delegated File Reading (via core module) ---");
    System.out.println();

    // Create a test config file
    try {
      Path configDir = Path.of("config");
      Files.createDirectories(configDir);
      Files.writeString(configDir.resolve("app.conf"), "setting=value\n");
    } catch (Exception e) {
      System.out.println("  Setup: Could not create test config file: " + e.getMessage());
    }

    System.out.println("[DELEGATED] ConfigReader.readConfig(\"app.conf\")");
    System.out.println("  (Core module has fs.read entitlement for config/)");
    try {
      String content = ConfigReader.readConfig("app.conf");
      System.out.println("  SUCCESS: Read config = " + content.trim());
    } catch (SecurityException e) {
      System.out.println("  BLOCKED: " + e.getMessage());
    } catch (Exception e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  private static void testDirectFileReading() {
    System.out.println("--- TEST 3: Direct File Reading (from app module) ---");
    System.out.println();

    System.out.println("[NOT ENTITLED] Files.readString(Path.of(\"config/app.conf\"))");
    System.out.println("  (App module does NOT have fs.read entitlement)");
    try {
      String content = Files.readString(Path.of("config/app.conf"));
      System.out.println("  SUCCESS (unexpected): Read = " + content.trim());
      System.out.println("  (This should be BLOCKED when running with the agent!)");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (Exception e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
    System.out.println("[NOT ENTITLED] Reading /etc/passwd");
    try {
      String content = Files.readString(Path.of("/etc/passwd"));
      System.out.println("  SUCCESS (unexpected): Read " + content.length() + " bytes");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (Exception e) {
      System.out.println("  ERROR: " + e.getMessage());
    }

    System.out.println();
  }

  private static void testDelegatedNetworkAccess() {
    System.out.println("--- TEST 4: Delegated Network Access (via network module) ---");
    System.out.println();

    System.out.println("[DELEGATED] SimpleHttpClient.tryConnect(\"httpbin.org\", 443)");
    System.out.println("  (Network module has network.outbound entitlement for httpbin.org)");
    String result = SimpleHttpClient.tryConnect("httpbin.org", 443);
    System.out.println("  Result: " + result);

    System.out.println();
    System.out.println("[DELEGATED] SimpleHttpClient.tryConnect(\"evil.com\", 443)");
    System.out.println("  (Network module does NOT have entitlement for evil.com)");
    result = SimpleHttpClient.tryConnect("evil.com", 443);
    System.out.println("  Result: " + result);

    System.out.println();
  }

  private static void testDirectNetworkAccess() {
    System.out.println("--- TEST 5: Direct Network Access (from app module) ---");
    System.out.println();

    System.out.println("[NOT ENTITLED] new Socket(\"httpbin.org\", 443)");
    System.out.println("  (App module does NOT have network.outbound entitlement)");
    try (var socket = new java.net.Socket("httpbin.org", 443)) {
      System.out.println("  SUCCESS (unexpected): Connected to httpbin.org:443");
      System.out.println("  (This should be BLOCKED when running with the agent!)");
    } catch (SecurityException e) {
      System.out.println("  BLOCKED (expected): " + e.getMessage());
    } catch (Exception e) {
      System.out.println("  Connection result: " + e.getMessage());
    }

    System.out.println();
  }
}
