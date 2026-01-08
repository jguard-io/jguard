/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.multimodule.network;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Simple HTTP client for making network requests.
 *
 * <p>This class is in the network module which has network.outbound entitlement for specific hosts.
 * Network connections made from this module will be allowed to entitled hosts.
 */
public final class SimpleHttpClient {

  private static final HttpClient CLIENT =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

  private SimpleHttpClient() {}

  /**
   * Fetches content from a URL.
   *
   * @param url the URL to fetch
   * @return the response body as a string
   * @throws IOException if the request fails
   * @throws InterruptedException if the request is interrupted
   */
  public static String fetch(String url) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();

    HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    return response.body();
  }

  /**
   * Checks if a host:port is reachable by attempting a TCP connection.
   *
   * @param host the host to connect to
   * @param port the port to connect to
   * @return true if connection succeeded, false otherwise
   */
  public static boolean checkConnection(String host, int port) {
    try (Socket socket = new Socket(host, port)) {
      return socket.isConnected();
    } catch (IOException e) {
      // Connection failed - could be network issue or security denial
      return false;
    }
  }

  /**
   * Attempts a connection to demonstrate entitled vs non-entitled access.
   *
   * @param host the host to connect to
   * @param port the port to connect to
   * @return a status message
   */
  public static String tryConnect(String host, int port) {
    try (Socket socket = new Socket(host, port)) {
      return "Connected successfully to " + host + ":" + port;
    } catch (SecurityException e) {
      return "BLOCKED by jGuard: " + e.getMessage();
    } catch (IOException e) {
      return "Connection failed (network issue): " + e.getMessage();
    }
  }
}
