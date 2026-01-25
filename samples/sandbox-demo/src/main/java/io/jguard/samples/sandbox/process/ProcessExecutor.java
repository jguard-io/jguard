/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.process;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Demonstrates the process.exec capability.
 *
 * <p>This class is entitled to execute only /bin/echo and /usr/bin/echo commands. Attempting to
 * execute other commands will result in a SecurityException.
 */
public final class ProcessExecutor {

  private ProcessExecutor() {}

  /**
   * Executes an echo command and returns its output.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.process to
   * process.exec("/bin/echo")}
   *
   * @param message the message to echo
   * @return the echoed output
   * @throws IOException if an I/O error occurs
   * @throws InterruptedException if the process is interrupted
   */
  public static String echo(String message) throws IOException, InterruptedException {
    // Try /bin/echo first, fall back to /usr/bin/echo
    String echoPath = new java.io.File("/bin/echo").exists() ? "/bin/echo" : "/usr/bin/echo";

    ProcessBuilder pb = new ProcessBuilder(echoPath, message);
    pb.redirectErrorStream(true);
    Process process = pb.start();

    StringBuilder output = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(process.getInputStream()))) {
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line);
      }
    }

    int exitCode = process.waitFor();
    if (exitCode != 0) {
      throw new IOException("Process exited with code: " + exitCode);
    }

    return output.toString();
  }

  /**
   * Attempts to execute an unauthorized command (should be blocked).
   *
   * <p>This method attempts to run /bin/ls which is NOT entitled. It should throw a
   * SecurityException when jGuard is active.
   *
   * @throws IOException if an I/O error occurs
   * @throws SecurityException if not entitled (expected)
   */
  public static void attemptUnauthorizedExec() throws IOException {
    // This should be blocked - we're only entitled to /bin/echo
    Runtime.getRuntime().exec("/bin/ls");
  }
}
