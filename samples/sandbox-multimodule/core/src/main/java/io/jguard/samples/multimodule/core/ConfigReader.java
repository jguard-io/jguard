/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.multimodule.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Reads configuration files and provides core utilities.
 *
 * <p>This class is in the core module which has:
 *
 * <ul>
 *   <li>fs.read entitlement for the "config" directory
 *   <li>fs.write entitlement for "build/output"
 *   <li>process.exec entitlement for /bin/echo
 *   <li>fs.hardlink entitlement for "build/output"
 * </ul>
 *
 * <p>When called from another module (like app), the security check uses the CALLER's module, not
 * this class's module. So direct file access from app module will be denied.
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

  // ========== v0.3 Capabilities ==========

  /**
   * Executes an echo command (v0.3 process.exec capability).
   *
   * <p>This method is entitled via: {@code entitle module to process.exec("/bin/echo")}
   *
   * @param message the message to echo
   * @return the command output
   */
  public static String executeEcho(String message) {
    try {
      String echoPath = Files.exists(Path.of("/bin/echo")) ? "/bin/echo" : "/usr/bin/echo";
      ProcessBuilder pb = new ProcessBuilder(echoPath, message);
      pb.redirectErrorStream(true);
      Process process = pb.start();

      String output;
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        output = reader.lines().collect(Collectors.joining("\n"));
      }

      int exitCode = process.waitFor();
      if (exitCode != 0) {
        return "ERROR: Exit code " + exitCode;
      }
      return output;
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to execute an unauthorized command (v0.3 - should be blocked).
   *
   * @return result message
   */
  public static String executeUnauthorized() {
    try {
      ProcessBuilder pb = new ProcessBuilder("/bin/ls", "-la");
      pb.start();
      return "SUCCESS (unexpected) - /bin/ls executed";
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Creates a hard link in the build output directory (v0.3 fs.hardlink capability).
   *
   * <p>This method is entitled via: {@code entitle module to fs.hardlink("build/output", "**")}
   *
   * @param sourceName the source file name
   * @param linkName the link name
   * @return result message
   */
  public static String createHardLink(String sourceName, String linkName) {
    try {
      Path outputDir = Path.of("build/output");
      Files.createDirectories(outputDir);

      Path source = outputDir.resolve(sourceName);
      if (!Files.exists(source)) {
        Files.writeString(source, "Source file for hard link test\n");
      }

      Path link = outputDir.resolve(linkName);
      Files.deleteIfExists(link);
      Files.createLink(link, source);

      return "Created hard link: " + link + " -> " + source;
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      return "ERROR: " + e.getMessage();
    }
  }

  /**
   * Attempts to create a hard link in an unauthorized directory (v0.3 - should be blocked).
   *
   * @return result message
   */
  public static String createUnauthorizedHardLink() {
    try {
      Path source = Path.of("build/output/source.txt");
      Files.createDirectories(source.getParent());
      if (!Files.exists(source)) {
        Files.writeString(source, "Source file\n");
      }

      Path link = Path.of("/tmp/jguard-unauthorized-link");
      Files.deleteIfExists(link);
      Files.createLink(link, source);
      Files.deleteIfExists(link);

      return "SUCCESS (unexpected) - hard link created in /tmp";
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    } catch (Exception e) {
      return "ERROR: " + e.getMessage();
    }
  }
}
