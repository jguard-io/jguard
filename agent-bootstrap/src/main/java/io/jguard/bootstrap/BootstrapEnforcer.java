/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;

/**
 * Bootstrap enforcement bridge for jGuard.
 *
 * <p>This class is injected into the bootstrap classloader and serves as the bridge between
 * instrumented JDK classes and the jGuard agent. It is designed to:
 *
 * <ul>
 *   <li>Only reference JDK classes (no external dependencies)
 *   <li>Handle all enforcement modes correctly
 *   <li>Fail safely in all error scenarios
 *   <li>Provide consistent logging
 * </ul>
 *
 * <h2>Architecture</h2>
 *
 * <pre>{@code
 * JDK Class (Files.readString)
 *       |
 *       v
 * ByteBuddy Advice (FilesystemInterceptor)
 *       |
 *       v
 * BootstrapEnforcer.onFileRead()    <- bootstrap classloader
 *       |
 *       v (single dispatch)
 * EnforcementCallback.check()       <- set by agent
 *       |
 *       v
 * PolicyEnforcer                    <- agent classloader
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>All fields are volatile and methods are thread-safe. The callback returns null for allowed, or
 * a SecurityException for denied.
 */
public final class BootstrapEnforcer {

  private static final AgentLogger LOG = AgentLogger.getLogger(BootstrapEnforcer.class);

  /** Default skip prefixes for caller attribution. */
  private static final String[] DEFAULT_SKIP_PREFIXES = {
    // jGuard infrastructure - be specific to avoid matching application packages
    "io.jguard.bootstrap.",
    "io.jguard.agent.",
    // ByteBuddy internals (agent uses relocated version too)
    "net.bytebuddy.",
    "io.jguard.internal.bytebuddy.",
    // JDK internals
    "java.",
    "sun.",
    "com.sun.",
    "jdk.",
    "jdk.internal."
  };

  /** Single enforcement callback for all operations. */
  private static volatile EnforcementCallback callback;

  /** Current enforcement mode. */
  private static volatile EnforcementMode mode = EnforcementMode.STRICT;

  /** Whether to log denied operations. */
  private static volatile boolean logDenied = true;

  /** Whether to log allowed operations. */
  private static volatile boolean logAllowed = false;

  /** Skip prefixes for caller attribution. */
  private static volatile String[] skipPrefixes = DEFAULT_SKIP_PREFIXES;

  /** Flag to prevent re-entrant calls during enforcement. */
  private static final ThreadLocal<Boolean> IN_ENFORCEMENT = new ThreadLocal<>();

  private BootstrapEnforcer() {}

  // ========== CONFIGURATION ==========

  /**
   * Configures the enforcement callback.
   *
   * <p>Called by the agent during initialization.
   *
   * @param cb the callback that checks if operations are allowed
   */
  public static void setCallback(EnforcementCallback cb) {
    callback = cb;
    LOG.debug("Enforcement callback configured");
  }

  /**
   * Sets the enforcement mode.
   *
   * @param enforcementMode the mode to use
   */
  public static void setMode(EnforcementMode enforcementMode) {
    mode = enforcementMode;
    LOG.debug("Enforcement mode set to: {}", enforcementMode);
  }

  /**
   * Configures logging behavior.
   *
   * @param denied whether to log denied operations
   * @param allowed whether to log allowed operations
   */
  public static void setLogging(boolean denied, boolean allowed) {
    logDenied = denied;
    logAllowed = allowed;
  }

  /**
   * Configures skip prefixes for caller attribution.
   *
   * <p>Classes matching these prefixes are skipped when walking the stack to find the caller.
   *
   * @param prefixes the prefixes to skip, or null to use defaults
   */
  public static void setSkipPrefixes(String[] prefixes) {
    skipPrefixes = (prefixes == null) ? DEFAULT_SKIP_PREFIXES : prefixes.clone();
  }

  // ========== FILESYSTEM READ ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a file read operation is intercepted (File variant).
   *
   * @param file the file being read
   */
  public static void onFileRead(File file) {
    if (file != null) {
      dispatch(Operation.FS_READ, file.toPath(), 0);
    }
  }

  /**
   * Called by ByteBuddy advice when a file read operation is intercepted (String variant).
   *
   * @param pathString the path string being read
   */
  public static void onFileRead(String pathString) {
    if (pathString != null) {
      dispatch(Operation.FS_READ, Path.of(pathString), 0);
    }
  }

  /**
   * Called by ByteBuddy advice when a file read operation is intercepted.
   *
   * @param path the path being read
   */
  public static void onFileRead(Path path) {
    dispatch(Operation.FS_READ, path, 0);
  }

  // ========== FILESYSTEM WRITE ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted (File variant).
   *
   * @param file the file being written
   */
  public static void onFileWrite(File file) {
    if (file != null) {
      dispatch(Operation.FS_WRITE, file.toPath(), 0);
    }
  }

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted (String variant).
   *
   * @param pathString the path string being written
   */
  public static void onFileWrite(String pathString) {
    if (pathString != null) {
      dispatch(Operation.FS_WRITE, Path.of(pathString), 0);
    }
  }

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted.
   *
   * @param path the path being written
   */
  public static void onFileWrite(Path path) {
    dispatch(Operation.FS_WRITE, path, 0);
  }

  // ========== NETWORK OUTBOUND ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a network connect operation is intercepted (host/port variant).
   *
   * @param host the host being connected to
   * @param port the port being connected to
   */
  public static void onNetworkConnect(String host, int port) {
    dispatch(Operation.NET_CONNECT, host, port);
  }

  /**
   * Called by ByteBuddy advice when a network connect operation is intercepted (InetSocketAddress
   * variant).
   *
   * @param address the socket address being connected to
   */
  public static void onNetworkConnect(InetSocketAddress address) {
    if (address != null) {
      dispatch(Operation.NET_CONNECT, address.getHostString(), address.getPort());
    }
  }

  /**
   * Called by ByteBuddy advice when a network connect operation is intercepted (InetAddress
   * variant).
   *
   * @param address the address being connected to
   * @param port the port being connected to
   */
  public static void onNetworkConnect(InetAddress address, int port) {
    if (address != null) {
      dispatch(Operation.NET_CONNECT, address.getHostAddress(), port);
    }
  }

  // ========== NETWORK LISTEN ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a server socket bind operation is intercepted (port variant).
   *
   * @param port the port being bound to (0 = bind-any-port)
   */
  public static void onNetworkListen(int port) {
    dispatch(Operation.NET_LISTEN, null, port);
  }

  /**
   * Called by ByteBuddy advice when a server socket bind operation is intercepted
   * (InetSocketAddress variant).
   *
   * @param address the socket address being bound to
   */
  public static void onNetworkListen(InetSocketAddress address) {
    dispatch(Operation.NET_LISTEN, null, address != null ? address.getPort() : 0);
  }

  // ========== THREAD CREATION ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a thread is being started.
   *
   * @param thread the thread being started
   */
  public static void onThreadCreate(Thread thread) {
    dispatch(Operation.THREAD_CREATE, thread != null ? thread.getName() : "unnamed", 0);
  }

  // ========== NATIVE LIBRARY ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a native library is being loaded.
   *
   * @param libraryName the name of the library being loaded
   */
  public static void onNativeLoad(String libraryName) {
    String libName = libraryName != null ? libraryName : "unknown";
    dispatch(Operation.NATIVE_LOAD, libName, 0);
  }

  // ========== ENVIRONMENT VARIABLE ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when an environment variable is being read.
   *
   * @param name the env var name, or null if reading all (System.getenv())
   */
  public static void onEnvRead(String name) {
    dispatch(Operation.ENV_READ, name, 0);
  }

  // ========== SYSTEM PROPERTY ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a system property is being read.
   *
   * @param key the property key, or null if reading all (System.getProperties())
   */
  public static void onPropertyRead(String key) {
    dispatch(Operation.PROP_READ, key, 0);
  }

  /**
   * Called by ByteBuddy advice when a system property is being written.
   *
   * @param key the property key, or null if replacing all (System.setProperties())
   */
  public static void onPropertyWrite(String key) {
    dispatch(Operation.PROP_WRITE, key, 0);
  }

  // ========== SINGLE DISPATCH ==========

  /**
   * Central dispatch point for all enforcement operations.
   *
   * <p>All entry points normalize their arguments and call this method. This ensures:
   *
   * <ul>
   *   <li>Reentrancy prevention is handled in one place
   *   <li>Caller attribution is handled in one place
   *   <li>Error handling is handled in one place
   *   <li>Logging is handled in one place
   * </ul>
   */
  private static void dispatch(Operation op, Object arg0, int arg1) {
    // Prevent re-entrancy - if we're already in enforcement, allow
    if (Boolean.TRUE.equals(IN_ENFORCEMENT.get())) {
      return;
    }

    EnforcementCallback cb = callback;
    if (cb == null) {
      // Agent not initialized - allow (JVM bootstrap)
      return;
    }

    try {
      IN_ENFORCEMENT.set(Boolean.TRUE);
      enforce(op, arg0, arg1, cb);
    } finally {
      IN_ENFORCEMENT.remove();
    }
  }

  /**
   * Performs the actual enforcement.
   *
   * <p>This method assumes reentrancy prevention is already handled.
   */
  private static void enforce(Operation op, Object arg0, int arg1, EnforcementCallback cb) {
    // Determine caller
    CallerInfo caller;
    try {
      caller = determineCallerInfo();
    } catch (Exception e) {
      handleError(op, arg0, arg1, "Failed to determine caller", e);
      return;
    }

    // Unknown caller = JVM internal operation, allow in all modes
    if (!caller.known()) {
      LOG.debug("Allowing {} from unknown caller (JVM internal)", op);
      return;
    }

    // Validate argument types (catches advice wiring bugs)
    if (!validateArgs(op, arg0, arg1)) {
      handleError(op, arg0, arg1, "Invalid args for op", null);
      return;
    }

    // Call the enforcement callback
    try {
      SecurityException denial = cb.check(caller.toContext(), op, arg0, arg1);

      if (denial != null) {
        // Access denied
        if (logDenied) {
          LOG.warn(
              "DENIED {}: package={}, module={}, args={}",
              op,
              caller.packageName(),
              caller.moduleName(),
              formatArgs(op, arg0, arg1));
        }
        if (mode.blocksOnDenied()) {
          throw denial;
        }
      } else {
        // Access allowed
        if (logAllowed) {
          LOG.info(
              "ALLOWED {}: package={}, module={}", op, caller.packageName(), caller.moduleName());
        }
      }
    } catch (SecurityException se) {
      // Re-throw security exceptions
      throw se;
    } catch (Exception e) {
      handleError(op, arg0, arg1, "Enforcement callback failed", e);
    }
  }

  // ========== HELPERS ==========

  /**
   * Formats operation arguments for logging.
   *
   * <p>Uses the operation's category to determine format. Adding new operations with existing
   * categories requires no changes here.
   */
  private static String formatArgs(Operation op, Object arg0, int arg1) {
    return switch (op.category()) {
      case FILESYSTEM -> String.valueOf(arg0);
      case SIMPLE -> arg0 != null ? arg0 + ":" + arg1 : "n/a";
      case PORT -> "port=" + arg1;
      case TARGET_PATTERN -> arg0 != null ? String.valueOf(arg0) : "any";
      case HOST_PORT -> (arg0 != null ? arg0 : "*") + ":" + arg1;
    };
  }

  /**
   * Validates argument types for an operation.
   *
   * <p>Uses the operation's category to determine expected types. Adding new operations with
   * existing categories requires no changes here.
   */
  private static boolean validateArgs(Operation op, Object arg0, int arg1) {
    return switch (op.category()) {
      case FILESYSTEM -> arg0 instanceof Path;
      case SIMPLE -> true; // No strict type requirement
      case PORT -> true; // arg0 is null, arg1 is port
      case TARGET_PATTERN -> arg0 == null || arg0 instanceof String;
      case HOST_PORT -> arg0 == null || arg0 instanceof String; // arg0 is host, arg1 is port
    };
  }

  /**
   * Handles errors during enforcement.
   *
   * <p>Applies {@code mode.blocksOnError()} semantics: throws SecurityException in STRICT
   * (fail-closed), logs and allows in PERMISSIVE/AUDIT.
   */
  private static void handleError(
      Operation op, Object arg0, int arg1, String context, Exception e) {
    String args = formatArgs(op, arg0, arg1);
    if (mode.blocksOnError()) {
      String msg = e != null ? e.getMessage() : "unknown error";
      LOG.error("{}: {} - blocking {} for {}", context, msg, op, args);
      throw new SecurityException("jGuard: enforcement error - " + context + ": " + msg);
    } else {
      String msg = e != null ? e.getMessage() : "unknown error";
      LOG.warn("{}: {} - allowing {} for {} (mode={})", context, msg, op, args, mode);
    }
  }

  // ========== CALLER ATTRIBUTION ==========

  /**
   * Determines the calling code's package and module.
   *
   * <p>Walks the stack to find the first frame that is application code (not JDK, jGuard, or
   * ByteBuddy infrastructure).
   */
  private static CallerInfo determineCallerInfo() {
    return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
        .walk(
            frames ->
                frames
                    .map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(BootstrapEnforcer::isApplicationCode)
                    .findFirst()
                    .map(CallerInfo::from)
                    .orElse(CallerInfo.UNKNOWN));
  }

  /**
   * Checks if a class is application code (not infrastructure).
   *
   * <p>Uses the configurable skipPrefixes to determine what to skip.
   */
  private static boolean isApplicationCode(Class<?> clazz) {
    String name = clazz.getName();

    // Skip infrastructure classes matching skip prefixes
    for (String prefix : skipPrefixes) {
      if (name.startsWith(prefix)) {
        return false;
      }
    }

    // Skip lambda and proxy classes - these are synthetic and we need to find the real caller
    // Lambda classes are named like: com.example.Foo$$Lambda$123/0x...
    // Proxy classes are named like: com.sun.proxy.$Proxy0
    if (name.contains("$$Lambda$") || name.contains(".$Proxy")) {
      return false;
    }

    // Skip reflection and MethodHandle classes that might appear on stack
    // When code uses Method.invoke() or MethodHandle.invoke(), these frames appear
    // but the actual caller is further up the stack
    if (name.startsWith("java.lang.reflect.")
        || name.startsWith("java.lang.invoke.")
        || name.startsWith("jdk.internal.reflect.")) {
      return false;
    }

    return true;
  }

  // ========== INTERNAL TYPES ==========

  /**
   * Information about the caller making a capability request (internal).
   *
   * <p>Uses a boolean sentinel {@code known()} instead of string comparison for unknown callers.
   */
  private record CallerInfo(String packageName, String moduleName, boolean known) {
    static final CallerInfo UNKNOWN = new CallerInfo("", "", false);

    static CallerInfo from(Class<?> clazz) {
      Module module = clazz.getModule();
      String moduleName = module.isNamed() ? module.getName() : "unnamed";
      return new CallerInfo(clazz.getPackageName(), moduleName, true);
    }

    CallerContext toContext() {
      return new CallerContext(packageName, moduleName);
    }
  }
}
