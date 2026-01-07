/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.net;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * Network server that is entitled to listen on server sockets.
 *
 * <p>This class is in the {@code io.jguard.samples.sandbox.net} package, which is granted
 * {@code network.listen} capability in the module policy.
 */
public final class NetworkServer {

  private NetworkServer() {}

  /**
   * Attempts to create a ServerSocket and bind to a port.
   *
   * @param port the port to bind to (0 for any available port)
   * @return the bound port number if successful, -1 if failed
   * @throws SecurityException if the operation is blocked by jGuard
   */
  public static int tryListen(int port) {
    try (ServerSocket serverSocket = new ServerSocket(port)) {
      // Successfully bound to the port
      return serverSocket.getLocalPort();
    } catch (IOException e) {
      // Bind failed (port in use or other network issue)
      return -1;
    }
  }
}
