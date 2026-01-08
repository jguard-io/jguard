/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.multimodule.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Reads configuration files.
 *
 * <p>This class is in the core module which has fs.read entitlement for the "config" directory.
 * When called from another module (like app), the security check uses the CALLER's module, not
 * this class's module. So direct file access from app module will be denied.
 *
 * <p>To allow app to read configs safely, use the delegated methods that perform the read within
 * this module's context.
 */
public final class ConfigReader {

  private ConfigReader() {}

  /**
   * Reads a configuration file from the config directory.
   *
   * <p>This method performs the file read within the core module's security context, so it will
   * succeed if the core module has fs.read entitlement for the config directory.
   *
   * @param filename the config file name (relative to config/)
   * @return the file contents as a string
   * @throws IOException if the file cannot be read
   */
  public static String readConfig(String filename) throws IOException {
    Path configPath = Path.of("config", filename);
    return Files.readString(configPath);
  }

  /**
   * Lists all configuration files in the config directory.
   *
   * @return list of config file names
   * @throws IOException if the directory cannot be read
   */
  public static List<String> listConfigs() throws IOException {
    Path configDir = Path.of("config");
    if (!Files.isDirectory(configDir)) {
      return List.of();
    }
    try (var stream = Files.list(configDir)) {
      return stream.map(p -> p.getFileName().toString()).sorted().toList();
    }
  }

  /**
   * Reads a file from the current directory (for demo purposes).
   *
   * @param filename the file name
   * @return the file contents
   * @throws IOException if the file cannot be read
   */
  public static String readFile(String filename) throws IOException {
    return Files.readString(Path.of(filename));
  }

  /**
   * Attempts to read a file using direct NIO - will use caller's module context.
   *
   * <p>This method demonstrates that jGuard checks the CALLER's module, not the declaring class's
   * module. When called from the app module, this will be denied because app doesn't have fs.read.
   *
   * @param path the path to read
   * @return the file contents
   * @throws IOException if the file cannot be read
   */
  public static String readDirect(Path path) throws IOException {
    // Note: The security check happens here, but uses the CALLER's module
    // because jGuard walks the stack to find the actual caller
    return Files.readString(path);
  }
}
