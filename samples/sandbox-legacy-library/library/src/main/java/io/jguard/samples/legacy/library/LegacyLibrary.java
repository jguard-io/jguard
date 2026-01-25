/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.legacy.library;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.stream.Collectors;

/**
 * Simulates a third-party library that was NOT built with jGuard.
 *
 * <p>This library has NO embedded jGuard policy. It represents the common case of:
 *
 * <ul>
 *   <li>Open source libraries from Maven Central
 *   <li>Legacy internal libraries
 *   <li>Any JAR without jGuard integration
 * </ul>
 *
 * <p>Without an external policy granting capabilities, jGuard will BLOCK all sensitive operations
 * from this library (restrictive by default).
 */
public class LegacyLibrary {

  /**
   * Attempts to read a configuration file.
   *
   * @param configPath the path to read
   * @return result message
   */
  public static String readConfig(String configPath) {
    System.out.println("[LegacyLib] Attempting to read config: " + configPath);
    try {
      String content = Files.readString(Path.of(configPath));
      System.out.println("[LegacyLib] \u2713 Read config successfully (" + content.length() + " bytes)");
      return "SUCCESS: " + content.length() + " bytes";
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    } catch (IOException e) {
      System.out.println("[LegacyLib] \u2717 IO error: " + e.getMessage());
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to make an HTTP request.
   *
   * @param url the URL to fetch
   * @return result message
   */
  public static String fetchUrl(String url) {
    System.out.println("[LegacyLib] Attempting HTTP request: " + url);
    try {
      URL urlObj = new URL(url);
      HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
      conn.setRequestMethod("GET");
      conn.setConnectTimeout(5000);
      int responseCode = conn.getResponseCode();
      System.out.println("[LegacyLib] \u2713 HTTP response: " + responseCode);
      conn.disconnect();
      return "SUCCESS: HTTP " + responseCode;
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      System.out.println("[LegacyLib] \u2717 Error: " + e.getMessage());
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to read a system property.
   *
   * @param key the property key
   * @return result message
   */
  public static String getProperty(String key) {
    System.out.println("[LegacyLib] Attempting to read property: " + key);
    try {
      String value = System.getProperty(key);
      System.out.println("[LegacyLib] \u2713 Property value: " + value);
      return "SUCCESS: " + value;
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    }
  }

  /**
   * Attempts to create a thread.
   *
   * @return result message
   */
  public static String createThread() {
    System.out.println("[LegacyLib] Attempting to create thread");
    try {
      Thread thread = new Thread(() -> System.out.println("[LegacyLib] Thread running!"));
      thread.start();
      thread.join(1000);
      System.out.println("[LegacyLib] \u2713 Thread created and completed");
      return "SUCCESS";
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    } catch (InterruptedException e) {
      return "INTERRUPTED";
    }
  }

  // ========== v0.3 Capabilities ==========

  /**
   * Attempts to execute a process.
   *
   * @param command the command to execute
   * @return result message
   */
  public static String executeProcess(String command) {
    System.out.println("[LegacyLib] Attempting to execute: " + command);
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
      System.out.println("[LegacyLib] \u2713 Process executed (exit " + exitCode + "): " + output);
      return "SUCCESS: " + output;
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      System.out.println("[LegacyLib] \u2717 Error: " + e.getMessage());
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to create a hard link.
   *
   * @param source the source file
   * @param link the link path
   * @return result message
   */
  public static String createHardLink(Path source, Path link) {
    System.out.println("[LegacyLib] Attempting hard link: " + link + " -> " + source);
    try {
      Files.deleteIfExists(link);
      Files.createLink(link, source);
      System.out.println("[LegacyLib] \u2713 Hard link created");
      Files.deleteIfExists(link);
      return "SUCCESS";
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    } catch (IOException e) {
      System.out.println("[LegacyLib] \u2717 IO error: " + e.getMessage());
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to add a crypto provider.
   *
   * @return result message
   */
  public static String addCryptoProvider() {
    System.out.println("[LegacyLib] Attempting to add crypto provider");
    try {
      Provider testProvider =
          new Provider("LegacyTestProvider", "1.0", "Legacy library test provider") {
            private static final long serialVersionUID = 1L;
          };
      int position = Security.addProvider(testProvider);
      System.out.println("[LegacyLib] \u2713 Provider added at position " + position);
      Security.removeProvider("LegacyTestProvider");
      return "SUCCESS";
    } catch (SecurityException e) {
      System.out.println("[LegacyLib] \u2717 BLOCKED by jGuard: " + e.getMessage());
      return "BLOCKED: " + e.getMessage();
    }
  }
}
