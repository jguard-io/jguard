/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.legacy.library;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

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
}
