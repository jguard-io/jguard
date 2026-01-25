/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.fs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Demonstrates the fs.hardlink capability.
 *
 * <p>This class is entitled to create hard links only within the build/test-output directory.
 * Attempting to create hard links elsewhere will result in a SecurityException.
 */
public final class HardLinkCreator {

  private HardLinkCreator() {}

  /**
   * Creates a hard link within the entitled directory.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.fs to
   * fs.hardlink("build/test-output", "**")}
   *
   * @param existingFile the existing file to link to
   * @param linkName the name for the new link (created in build/test-output)
   * @return the path to the created link
   * @throws IOException if an I/O error occurs
   */
  public static Path createHardLink(Path existingFile, String linkName) throws IOException {
    Path outputDir = Path.of("build/test-output");
    Files.createDirectories(outputDir);

    Path link = outputDir.resolve(linkName);

    // Delete if exists from previous run
    Files.deleteIfExists(link);

    // Create the hard link
    return Files.createLink(link, existingFile);
  }

  /**
   * Attempts to create a hard link in an unauthorized location (should be blocked).
   *
   * <p>This method attempts to create a link in /tmp which is NOT entitled. It should throw a
   * SecurityException when jGuard is active.
   *
   * @param existingFile the existing file to link to
   * @throws IOException if an I/O error occurs
   * @throws SecurityException if not entitled (expected)
   */
  public static void attemptUnauthorizedHardLink(Path existingFile) throws IOException {
    // This should be blocked - we're only entitled to build/test-output
    Path link = Path.of("/tmp/unauthorized-link");
    Files.createLink(link, existingFile);
  }
}
