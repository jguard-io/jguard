/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.net;

import java.io.IOException;
import java.net.Socket;

/**
 * Network client that is entitled to make outbound connections.
 *
 * <p>This class is in the {@code io.jguard.samples.sandbox.net} package, which is granted
 * {@code network.outbound} capability in the module policy.
 */
public final class NetworkClient {

  private NetworkClient() {}

  /**
   * Attempts to establish a TCP connection to the specified host and port.
   *
   * @param host the host to connect to
   * @param port the port to connect to
   * @return true if connection was successful
   * @throws SecurityException if the operation is blocked by jGuard
   */
  public static boolean tryConnect(String host, int port) {
    try (Socket socket = new Socket(host, port)) {
      // Connection successful
      return true;
    } catch (IOException e) {
      // Connection failed (network issue, not security)
      return false;
    }
  }
}
