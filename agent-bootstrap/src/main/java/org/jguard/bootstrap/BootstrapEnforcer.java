/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

import java.io.File;
import java.nio.file.Path;
import java.util.function.BiFunction;

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
 *       v
 * enforcementCallback               <- BiFunction set by agent
 *       |
 *       v
 * PolicyEnforcer.checkFsRead()      <- agent classloader
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>All fields are volatile and methods are thread-safe. The callback is a BiFunction that returns
 * null for allowed, or a SecurityException for denied.
 */
public final class BootstrapEnforcer {

  private static final AgentLogger LOG = AgentLogger.getLogger(BootstrapEnforcer.class);

  /**
   * Callback for filesystem read enforcement.
   *
   * <p>Parameters: (callerContext, path) Returns: null if allowed, SecurityException if denied
   */
  private static volatile BiFunction<CallerContext, Path, SecurityException> fsReadCallback;

  /**
   * Callback for filesystem write enforcement.
   *
   * <p>Parameters: (callerContext, path) Returns: null if allowed, SecurityException if denied
   */
  private static volatile BiFunction<CallerContext, Path, SecurityException> fsWriteCallback;

  /** Current enforcement mode. */
  private static volatile EnforcementMode mode = EnforcementMode.STRICT;

  /** Whether to log denied operations. */
  private static volatile boolean logDenied = true;

  /** Whether to log allowed operations. */
  private static volatile boolean logAllowed = false;

  /** Flag to prevent re-entrant calls during enforcement. */
  private static final ThreadLocal<Boolean> IN_ENFORCEMENT = ThreadLocal.withInitial(() -> false);

  private BootstrapEnforcer() {}

  /**
   * Configures the filesystem read enforcement callback.
   *
   * <p>Called by the agent during initialization.
   *
   * @param callback function that takes (CallerContext, Path) and returns null if allowed,
   *     SecurityException if denied
   */
  public static void setFsReadCallback(
      BiFunction<CallerContext, Path, SecurityException> callback) {
    fsReadCallback = callback;
    LOG.debug("Filesystem read enforcement callback configured");
  }

  /**
   * Configures the filesystem write enforcement callback.
   *
   * <p>Called by the agent during initialization.
   *
   * @param callback function that takes (CallerContext, Path) and returns null if allowed,
   *     SecurityException if denied
   */
  public static void setFsWriteCallback(
      BiFunction<CallerContext, Path, SecurityException> callback) {
    fsWriteCallback = callback;
    LOG.debug("Filesystem write enforcement callback configured");
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
   * Called by ByteBuddy advice when a file read operation is intercepted (File variant).
   *
   * @param file the file being read
   */
  public static void onFileRead(File file) {
    if (file != null) {
      onFileRead(file.toPath());
    }
  }

  /**
   * Called by ByteBuddy advice when a file read operation is intercepted (String variant).
   *
   * @param pathString the path string being read
   */
  public static void onFileRead(String pathString) {
    if (pathString != null) {
      onFileRead(Path.of(pathString));
    }
  }

  /**
   * Called by ByteBuddy advice when a file read operation is intercepted.
   *
   * <p>This method handles all the complexity of enforcement:
   *
   * <ul>
   *   <li>Re-entrancy prevention (file operations during enforcement)
   *   <li>JVM bootstrap detection (allow before agent is ready)
   *   <li>Caller attribution with module verification
   *   <li>Enforcement mode handling
   *   <li>Error handling based on mode
   * </ul>
   *
   * @param path the path being read
   */
  public static void onFileRead(Path path) {
    // Prevent re-entrancy - if we're already in enforcement, allow
    if (Boolean.TRUE.equals(IN_ENFORCEMENT.get())) {
      return;
    }

    BiFunction<CallerContext, Path, SecurityException> callback = fsReadCallback;
    if (callback == null) {
      // Agent not initialized - allow (JVM bootstrap)
      return;
    }

    try {
      IN_ENFORCEMENT.set(true);
      enforceFileRead(path, callback);
    } finally {
      IN_ENFORCEMENT.set(false);
    }
  }

  private static void enforceFileRead(
      Path path, BiFunction<CallerContext, Path, SecurityException> callback) {
    CallerInfo caller;
    try {
      caller = determineCallerInfo();
    } catch (Exception e) {
      handleEnforcementError("Failed to determine caller", path, e);
      return;
    }

    String callerPackage = caller.packageName();
    String callerModule = caller.moduleName();

    // Handle unknown caller based on mode
    if ("unknown".equals(callerPackage)) {
      handleUnknownCaller("fs.read", path);
      return;
    }

    try {
      CallerContext context = caller.toContext();
      SecurityException denial = callback.apply(context, path);

      if (denial != null) {
        // Access denied
        if (logDenied) {
          LOG.warn(
              "DENIED fs.read: package={}, module={}, path={}", callerPackage, callerModule, path);
        }
        if (mode.blocksOnDenied()) {
          throw denial;
        }
      } else {
        // Access allowed
        if (logAllowed) {
          LOG.info(
              "ALLOWED fs.read: package={}, module={}, path={}", callerPackage, callerModule, path);
        }
      }
    } catch (SecurityException se) {
      // Re-throw security exceptions
      throw se;
    } catch (Exception e) {
      handleEnforcementError("Enforcement callback failed", path, e);
    }
  }

  private static void handleUnknownCaller(String operation, Path path) {
    // When the caller is "unknown", it typically means the call originated from JVM internals
    // (class loading, module loading, etc.) without any application code in the stack.
    // We must allow these operations for the JVM to function, even in STRICT mode.
    //
    // In STRICT mode, we log at DEBUG level to avoid noise from JVM bootstrap operations.
    // Actual application-initiated operations will always have application code on the stack.
    LOG.debug("Allowing {} from unknown caller (JVM internal): {}", operation, path);
  }

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted (File variant).
   *
   * @param file the file being written
   */
  public static void onFileWrite(File file) {
    if (file != null) {
      onFileWrite(file.toPath());
    }
  }

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted (String variant).
   *
   * @param pathString the path string being written
   */
  public static void onFileWrite(String pathString) {
    if (pathString != null) {
      onFileWrite(Path.of(pathString));
    }
  }

  /**
   * Called by ByteBuddy advice when a file write operation is intercepted.
   *
   * @param path the path being written
   */
  public static void onFileWrite(Path path) {
    // Prevent re-entrancy - if we're already in enforcement, allow
    if (Boolean.TRUE.equals(IN_ENFORCEMENT.get())) {
      return;
    }

    BiFunction<CallerContext, Path, SecurityException> callback = fsWriteCallback;
    if (callback == null) {
      // Agent not initialized - allow (JVM bootstrap)
      return;
    }

    try {
      IN_ENFORCEMENT.set(true);
      enforceFileWrite(path, callback);
    } finally {
      IN_ENFORCEMENT.set(false);
    }
  }

  private static void enforceFileWrite(
      Path path, BiFunction<CallerContext, Path, SecurityException> callback) {
    CallerInfo caller;
    try {
      caller = determineCallerInfo();
    } catch (Exception e) {
      handleEnforcementError("Failed to determine caller", path, e);
      return;
    }

    String callerPackage = caller.packageName();
    String callerModule = caller.moduleName();

    // Handle unknown caller based on mode
    if ("unknown".equals(callerPackage)) {
      handleUnknownCaller("fs.write", path);
      return;
    }

    try {
      CallerContext context = caller.toContext();
      SecurityException denial = callback.apply(context, path);

      if (denial != null) {
        // Access denied
        if (logDenied) {
          LOG.warn(
              "DENIED fs.write: package={}, module={}, path={}", callerPackage, callerModule, path);
        }
        if (mode.blocksOnDenied()) {
          throw denial;
        }
      } else {
        // Access allowed
        if (logAllowed) {
          LOG.info(
              "ALLOWED fs.write: package={}, module={}, path={}",
              callerPackage,
              callerModule,
              path);
        }
      }
    } catch (SecurityException se) {
      // Re-throw security exceptions
      throw se;
    } catch (Exception e) {
      handleEnforcementError("Enforcement callback failed", path, e);
    }
  }

  private static void handleEnforcementError(String context, Path path, Exception e) {
    if (mode.blocksOnError()) {
      LOG.error("{}: {} - blocking access to {}", context, e.getMessage(), path);
      throw new SecurityException("jGuard: enforcement error - " + context + ": " + e.getMessage());
    } else {
      LOG.warn("{}: {} - allowing access to {} (mode={})", context, e.getMessage(), path, mode);
    }
  }

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

  private static boolean isApplicationCode(Class<?> clazz) {
    String name = clazz.getName();

    // Skip jGuard infrastructure packages (but NOT sample apps or user code)
    if (name.startsWith("org.jguard.agent.")
        || name.startsWith("org.jguard.bootstrap.")
        || name.startsWith("org.jguard.core.")
        || name.startsWith("org.jguard.policy.")
        || name.startsWith("org.jguard.internal.")) {
      return false;
    }

    // Skip ByteBuddy (both original and relocated)
    if (name.startsWith("net.bytebuddy.")) {
      return false;
    }

    // Skip JDK infrastructure classes
    if (name.startsWith("sun.") || name.startsWith("jdk.") || name.startsWith("java.")) {
      return false;
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

  /** Information about the caller making a capability request (internal). */
  private record CallerInfo(String packageName, String moduleName) {
    static final CallerInfo UNKNOWN = new CallerInfo("unknown", "unknown");

    static CallerInfo from(Class<?> clazz) {
      Module module = clazz.getModule();
      String moduleName = module.isNamed() ? module.getName() : "unnamed";
      return new CallerInfo(clazz.getPackageName(), moduleName);
    }

    CallerContext toContext() {
      return new CallerContext(packageName, moduleName);
    }
  }

  /**
   * Context information about the caller making a capability request.
   *
   * <p>This record is passed to the enforcement callback and contains the caller's package name and
   * module name.
   *
   * @param packageName the caller's package name
   * @param moduleName the caller's module name, or "unnamed" for unnamed modules
   */
  public record CallerContext(String packageName, String moduleName) {}
}
