/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.net.restricted;

import java.io.IOException;
import java.net.Socket;

/**
 * Network client with restricted host/port filtering.
 *
 * <p>This class is in the {@code io.jguard.samples.sandbox.net.restricted} package, which is
 * granted limited {@code network.outbound("*.example.com", "80-443")} capability.
 *
 * <p>Connections to hosts matching {@code *.example.com} on ports 80-443 are allowed. All other
 * connections are denied.
 */
public final class RestrictedNetworkClient {

  private RestrictedNetworkClient() {}

  /**
   * Result of a connection attempt, distinguishing security denial from network failure.
   */
  public record ConnectionResult(boolean allowed, boolean connected, String message) {
    public static ConnectionResult allowed(boolean connected) {
      return new ConnectionResult(true, connected,
          connected ? "Connection successful" : "Connection allowed but failed (network issue)");
    }

    public static ConnectionResult denied(String reason) {
      return new ConnectionResult(false, false, "DENIED: " + reason);
    }
  }

  /**
   * Attempts to connect to the specified host and port.
   *
   * <p>This method is entitled to connect ONLY to:
   * <ul>
   *   <li>Hosts matching {@code *.example.com} (e.g., api.example.com, www.example.com)</li>
   *   <li>Ports in the range 80-443</li>
   * </ul>
   *
   * @param host the host to connect to
   * @param port the port to connect to
   * @return result indicating whether the connection was allowed and if it succeeded
   */
  public static ConnectionResult tryConnect(String host, int port) {
    try (Socket socket = new Socket(host, port)) {
      return ConnectionResult.allowed(true);
    } catch (SecurityException e) {
      return ConnectionResult.denied(e.getMessage());
    } catch (IOException e) {
      // Connection allowed but failed due to network (host unreachable, port closed, etc.)
      return ConnectionResult.allowed(false);
    }
  }
}
