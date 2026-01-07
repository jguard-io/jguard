/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.BootstrapEnforcer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice for intercepting network outbound operations.
 *
 * <p>This class contains static advice methods that are woven into JDK network classes to enforce
 * network.outbound entitlements.
 *
 * <p><b>Important:</b> All advice methods MUST only reference classes from the {@code
 * io.jguard.bootstrap} package and JDK classes. The bootstrap package is injected into the
 * bootstrap classloader, making it visible to transformed JDK classes. Any reference to
 * non-bootstrap classes will cause {@link NoClassDefFoundError} at runtime.
 */
public final class NetworkInterceptor {

  private NetworkInterceptor() {
    // Advice class
  }

  /**
   * Advice for Socket.connect(SocketAddress) and similar methods.
   *
   * <p>Applied to: Socket.connect(SocketAddress, int)
   */
  public static class SocketConnectAdvice {

    private SocketConnectAdvice() {}

    /**
     * Intercepts method entry to enforce network.outbound policy.
     *
     * @param address the socket address being connected to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) SocketAddress address) {
      if (address instanceof InetSocketAddress inetAddr) {
        BootstrapEnforcer.onNetworkConnect(inetAddr);
      }
    }
  }

  /**
   * Advice for Socket constructors that take host/port.
   *
   * <p>Applied to: Socket(String, int), Socket(InetAddress, int)
   */
  public static class SocketHostPortAdvice {

    private SocketHostPortAdvice() {}

    /**
     * Intercepts method entry to enforce network.outbound policy.
     *
     * @param host the host being connected to
     * @param port the port being connected to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String host, @Advice.Argument(1) int port) {
      BootstrapEnforcer.onNetworkConnect(host, port);
    }
  }

  /**
   * Advice for Socket constructors that take InetAddress/port.
   *
   * <p>Applied to: Socket(InetAddress, int)
   */
  public static class SocketInetAddressPortAdvice {

    private SocketInetAddressPortAdvice() {}

    /**
     * Intercepts method entry to enforce network.outbound policy.
     *
     * @param address the address being connected to
     * @param port the port being connected to
     */
    @Advice.OnMethodEnter
    public static void onEnter(
        @Advice.Argument(0) InetAddress address, @Advice.Argument(1) int port) {
      BootstrapEnforcer.onNetworkConnect(address, port);
    }
  }

  /**
   * Advice for SocketChannel.connect(SocketAddress).
   *
   * <p>Applied to: SocketChannel.connect(SocketAddress)
   */
  public static class SocketChannelConnectAdvice {

    private SocketChannelConnectAdvice() {}

    /**
     * Intercepts method entry to enforce network.outbound policy.
     *
     * @param address the socket address being connected to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) SocketAddress address) {
      if (address instanceof InetSocketAddress inetAddr) {
        BootstrapEnforcer.onNetworkConnect(inetAddr);
      }
    }
  }

  /**
   * Advice for URL.openConnection() and HttpClient connections.
   *
   * <p>Applied to: URL.openConnection(), HttpURLConnection.connect()
   *
   * <p>Note: URL.openConnection() returns a URLConnection but doesn't actually connect. The actual
   * connection happens in URLConnection.connect() or when reading/writing. For HTTP, we intercept
   * at the Socket level which catches all connections.
   */
  public static class UrlConnectionAdvice {

    private UrlConnectionAdvice() {}

    // This advice is a placeholder - actual enforcement happens at the Socket level
    // since all HTTP connections eventually go through Socket.connect()
  }

  // ========== NETWORK LISTEN (SERVER SOCKET) ADVICE ==========

  /**
   * Advice for ServerSocket constructors that take port.
   *
   * <p>Applied to: ServerSocket(int port), ServerSocket(int port, int backlog)
   */
  public static class ServerSocketPortAdvice {

    private ServerSocketPortAdvice() {}

    /**
     * Intercepts method entry to enforce network.listen policy.
     *
     * @param port the port being bound to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) int port) {
      BootstrapEnforcer.onNetworkListen(port);
    }
  }

  /**
   * Advice for ServerSocket.bind(SocketAddress).
   *
   * <p>Applied to: ServerSocket.bind(SocketAddress), ServerSocket.bind(SocketAddress, int)
   */
  public static class ServerSocketBindAdvice {

    private ServerSocketBindAdvice() {}

    /**
     * Intercepts method entry to enforce network.listen policy.
     *
     * @param address the socket address being bound to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) SocketAddress address) {
      if (address instanceof InetSocketAddress inetAddr) {
        BootstrapEnforcer.onNetworkListen(inetAddr);
      }
    }
  }

  /**
   * Advice for ServerSocketChannel.bind(SocketAddress).
   *
   * <p>Applied to: ServerSocketChannel.bind(SocketAddress), ServerSocketChannel.bind(SocketAddress,
   * int)
   */
  public static class ServerSocketChannelBindAdvice {

    private ServerSocketChannelBindAdvice() {}

    /**
     * Intercepts method entry to enforce network.listen policy.
     *
     * @param address the socket address being bound to
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) SocketAddress address) {
      if (address instanceof InetSocketAddress inetAddr) {
        BootstrapEnforcer.onNetworkListen(inetAddr);
      } else if (address == null) {
        // null means bind to any available port
        BootstrapEnforcer.onNetworkListen(0);
      }
    }
  }
}
