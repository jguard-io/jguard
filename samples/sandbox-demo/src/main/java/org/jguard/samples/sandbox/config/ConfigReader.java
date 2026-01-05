/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.samples.sandbox.config;

/**
 * Configuration reader with env.read and system.property.write capabilities.
 *
 * <p>This class is in the {@code org.jguard.samples.sandbox.config} package, which is granted:
 *
 * <ul>
 *   <li>{@code env.read} - can read any environment variable
 *   <li>{@code system.property.write("app.*")} - can write properties matching "app.*"
 * </ul>
 */
public final class ConfigReader {

  private ConfigReader() {}

  /**
   * Result of an env/property operation, distinguishing security denial from missing values.
   */
  public record ConfigResult(boolean allowed, String value, String message) {
    public static ConfigResult allowed(String value) {
      return new ConfigResult(true, value,
          value != null ? "Read successful" : "Key not found (but access allowed)");
    }

    public static ConfigResult denied(String reason) {
      return new ConfigResult(false, null, "DENIED: " + reason);
    }

    public static ConfigResult writeSuccess(String key, String value) {
      return new ConfigResult(true, value, "Write successful: " + key + "=" + value);
    }
  }

  /**
   * Reads an environment variable.
   *
   * <p>This package is entitled to {@code env.read}, so any env var can be read.
   *
   * @param name the environment variable name
   * @return result indicating whether access was allowed and the value
   */
  public static ConfigResult readEnv(String name) {
    try {
      String value = System.getenv(name);
      return ConfigResult.allowed(value);
    } catch (SecurityException e) {
      return ConfigResult.denied(e.getMessage());
    }
  }

  /**
   * Writes a system property.
   *
   * <p>This package is entitled to {@code system.property.write("app.*")}, so only properties
   * starting with "app." can be written.
   *
   * @param key the property key
   * @param value the property value
   * @return result indicating whether write was allowed
   */
  public static ConfigResult writeProperty(String key, String value) {
    try {
      System.setProperty(key, value);
      return ConfigResult.writeSuccess(key, value);
    } catch (SecurityException e) {
      return ConfigResult.denied(e.getMessage());
    }
  }

  /**
   * Clears a system property.
   *
   * <p>Clearing requires write permission for the property.
   *
   * @param key the property key to clear
   * @return result indicating whether clear was allowed
   */
  public static ConfigResult clearProperty(String key) {
    try {
      System.clearProperty(key);
      return new ConfigResult(true, null, "Clear successful: " + key);
    } catch (SecurityException e) {
      return ConfigResult.denied(e.getMessage());
    }
  }
}
