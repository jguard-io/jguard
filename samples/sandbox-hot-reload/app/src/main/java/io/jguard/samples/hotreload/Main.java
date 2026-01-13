/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package io.jguard.samples.hotreload;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Demonstrates jGuard's policy hot reload feature.
 *
 * <p>This application periodically tests various operations and displays their
 * allowed/blocked status. While running, you can modify the external policy files
 * and recompile them to see the changes take effect without restarting.
 *
 * <h2>How to use</h2>
 * <ol>
 *   <li>Run: {@code ./gradlew :app:runWithHotReload}</li>
 *   <li>In another terminal, edit {@code app/policies-src/io.jguard.samples.hotreload.jguard}</li>
 *   <li>Recompile: {@code ./gradlew :app:compileExternalPolicies}</li>
 *   <li>Watch the output change within 2 seconds!</li>
 * </ol>
 */
public final class Main {

  private static final int TEST_INTERVAL_SECONDS = 5;
  private static int iteration = 0;

  public static void main(String[] args) throws InterruptedException {
    printHeader();

    // Run tests in a loop
    while (true) {
      iteration++;
      System.out.println();
      System.out.printf("=== Test iteration %d ===%n", iteration);
      System.out.println();

      testFilesystemRead();
      testNetworkOutbound();
      testEnvRead();
      testThreadCreate();
      testPropertyRead();

      System.out.println();
      System.out.printf("Next test in %d seconds... (modify policies and recompile to see changes)%n",
          TEST_INTERVAL_SECONDS);
      System.out.println("-".repeat(70));

      TimeUnit.SECONDS.sleep(TEST_INTERVAL_SECONDS);
    }
  }

  private static void printHeader() {
    System.out.println("=".repeat(70));
    System.out.println("jGuard Hot Reload Demo");
    System.out.println("=".repeat(70));
    System.out.println();
    System.out.println("This demo tests various operations every " + TEST_INTERVAL_SECONDS + " seconds.");
    System.out.println("Modify app/policies-src/io.jguard.samples.hotreload.jguard and run:");
    System.out.println("  ./gradlew :app:compileExternalPolicies");
    System.out.println("to see hot reload in action!");
    System.out.println();
    System.out.println("The agent polls for changes every 2 seconds.");
    System.out.println("-".repeat(70));
  }

  private static void testFilesystemRead() {
    System.out.print("  fs.read .............. ");
    try {
      Path path = Path.of("build.gradle");
      if (Files.exists(path)) {
        Files.readString(path);
        System.out.println("ALLOWED");
      } else {
        System.out.println("ALLOWED (file not found, but permission granted)");
      }
    } catch (SecurityException e) {
      System.out.println("BLOCKED - " + extractReason(e));
    } catch (IOException e) {
      System.out.println("ALLOWED (I/O error: " + e.getMessage() + ")");
    }
  }

  private static void testNetworkOutbound() {
    System.out.print("  network.outbound ..... ");
    try (Socket socket = new Socket()) {
      // Just attempt to connect - we don't need it to succeed
      socket.connect(new InetSocketAddress("httpbin.org", 443), 1000);
      System.out.println("ALLOWED");
    } catch (SecurityException e) {
      System.out.println("BLOCKED - " + extractReason(e));
    } catch (IOException e) {
      // Connection failed but permission was granted
      System.out.println("ALLOWED (connection failed, but permission granted)");
    }
  }

  private static void testEnvRead() {
    System.out.print("  env.read ............. ");
    try {
      System.getenv("HOME");
      System.out.println("ALLOWED");
    } catch (SecurityException e) {
      System.out.println("BLOCKED - " + extractReason(e));
    }
  }

  private static void testThreadCreate() {
    System.out.print("  threads.create ....... ");
    try {
      Thread thread = new Thread(() -> {});
      thread.start();
      thread.join(100);
      System.out.println("ALLOWED");
    } catch (SecurityException e) {
      System.out.println("BLOCKED - " + extractReason(e));
    } catch (InterruptedException e) {
      System.out.println("ALLOWED (interrupted)");
    }
  }

  private static void testPropertyRead() {
    System.out.print("  system.property.read . ");
    try {
      System.getProperty("java.version");
      System.out.println("ALLOWED (always granted via embedded policy)");
    } catch (SecurityException e) {
      System.out.println("BLOCKED - " + extractReason(e));
    }
  }

  private static String extractReason(SecurityException e) {
    String msg = e.getMessage();
    if (msg != null && msg.contains("not entitled")) {
      return "not entitled";
    }
    return msg != null ? msg : "access denied";
  }
}
