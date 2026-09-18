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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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

  /**
   * One walker for the process.
   *
   * <p>{@code StackWalker.getInstance} allocates, and attribution runs on every intercepted
   * operation -- every property read, file open and socket connect the JVM performs. The instance
   * is immutable and thread-safe, so there is no reason to build one per call.
   */
  private static final StackWalker WALKER =
      StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

  /**
   * Attribution is a pure function of the calling class, so it is computed once per class.
   *
   * <p>A {@link ClassValue} is the right shape for this: it is keyed by {@code Class}, and it does
   * not pin classes the way a {@code Map<Class, ?>} would, so a host that loads and discards
   * classloaders is not leaked by the act of being guarded.
   *
   * <p>Holds the answer for classes that ARE application code. "No application frame anywhere on
   * the stack" is a property of a stack rather than of a class, so it is not cached -- {@link
   * #determineCallerContext()} returns null for it.
   */
  private static volatile ClassValue<CallerContext> callerContexts = newCallerContexts();

  /** Memoises the prefix scan, which otherwise re-tests nine prefixes per frame per call. */
  private static volatile ClassValue<Boolean> applicationCode = newApplicationCode();

  /** Flag to prevent re-entrant calls during enforcement. */
  private static final ThreadLocal<Boolean> IN_ENFORCEMENT = new ThreadLocal<>();

  // ========== AUDIT MODE DENIAL ACCUMULATION ==========

  /**
   * Represents a unique denial for audit mode accumulation.
   *
   * <p>Denials are considered unique based on (moduleName, packageName, operation, args).
   */
  record DenialRecord(String moduleName, String packageName, Operation operation, String args) {}

  /** Thread-safe set of accumulated denials in audit mode. */
  private static final Set<DenialRecord> auditDenials = ConcurrentHashMap.newKeySet();

  /** Flag to track if shutdown hook is registered. */
  private static volatile boolean shutdownHookRegistered = false;

  /** Lock object for shutdown hook registration. */
  private static final Object SHUTDOWN_HOOK_LOCK = new Object();

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
   * <p>When AUDIT mode is set, registers a JVM shutdown hook to log accumulated denials.
   *
   * @param enforcementMode the mode to use
   */
  public static void setMode(EnforcementMode enforcementMode) {
    mode = enforcementMode;
    LOG.debug("Enforcement mode set to: {}", enforcementMode);

    // Register shutdown hook for audit mode summary
    if (enforcementMode == EnforcementMode.AUDIT) {
      registerAuditShutdownHook();
    }
  }

  /**
   * Registers the audit mode shutdown hook if not already registered.
   *
   * <p>The hook logs a summary of all accumulated denials at JVM shutdown.
   */
  private static void registerAuditShutdownHook() {
    if (shutdownHookRegistered) {
      return;
    }

    synchronized (SHUTDOWN_HOOK_LOCK) {
      if (shutdownHookRegistered) {
        return;
      }

      Runtime.getRuntime()
          .addShutdownHook(
              new Thread(
                  () -> {
                    if (auditDenials.isEmpty()) {
                      return;
                    }

                    // Group denials by module
                    Map<String, List<DenialRecord>> byModule =
                        auditDenials.stream()
                            .collect(Collectors.groupingBy(DenialRecord::moduleName));

                    // Log summary header
                    LOG.warn(
                        "AUDIT SUMMARY: {} unique denial(s) across {} module(s)",
                        auditDenials.size(),
                        byModule.size());

                    // Log denials grouped by module
                    byModule.forEach(
                        (moduleName, denials) -> {
                          LOG.warn("  Module: {}", moduleName);
                          for (DenialRecord denial : denials) {
                            LOG.warn(
                                "    DENIED {}: package={}, args={}",
                                denial.operation(),
                                denial.packageName(),
                                denial.args());
                          }
                        });
                  },
                  "jguard-audit-summary"));

      shutdownHookRegistered = true;
      LOG.debug("Audit mode shutdown hook registered");
    }
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
   * Returns whether denied operations are logged.
   *
   * <p>Readable so a management interface can report what is in force rather than guess it from the
   * system properties the JVM started with, which stop being the truth the moment anything changes
   * either setting at runtime.
   *
   * @return true if denials are logged
   */
  public static boolean logDenied() {
    return logDenied;
  }

  /**
   * Returns whether allowed operations are logged.
   *
   * @return true if allowed operations are logged
   */
  public static boolean logAllowed() {
    return logAllowed;
  }

  /**
   * Returns the current enforcement mode.
   *
   * @return the mode in force
   */
  public static EnforcementMode mode() {
    return mode;
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
    // Both caches answered according to the OLD prefixes. ClassValue.remove is per key and the key
    // set is every class ever seen, so replace the caches wholesale rather than try to purge them.
    applicationCode = newApplicationCode();
    callerContexts = newCallerContexts();
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

  // ========== FILESYSTEM HARD LINK ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a hard link creation is intercepted.
   *
   * <p>The link path is checked against {@code fs.hardlink} entitlements. Note that creating a hard
   * link also implicitly requires {@code fs.read} on the existing file (to read its data) and
   * {@code fs.write} on the link's parent directory (to create the directory entry).
   *
   * @param link the link path being created
   * @param existing the existing file path being linked to
   */
  public static void onHardLink(Path link, Path existing) {
    // Check fs.hardlink on the link destination
    dispatch(Operation.FS_HARDLINK, link, 0);
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
   * <p>Special handling: If the immediate caller of System.loadLibrary is JDK code (java.*, jdk.*,
   * sun.*, com.sun.*), we allow the load without checking user entitlements. This is because the
   * JDK often loads native libraries as an internal implementation detail (e.g., network, crypto)
   * and user code shouldn't need to explicitly grant native.load for JDK internals.
   *
   * @param libraryName the name of the library being loaded
   */
  public static void onNativeLoad(String libraryName) {
    // Check if the immediate caller is JDK code loading its own libraries.
    // Stack: [0]=this method, [1]=System.loadLibrary, [2]=actual caller
    // If the actual caller is JDK code, allow it - JDK is loading its own internal libraries.
    if (isJdkInternalLibraryLoad()) {
      LOG.debug("Allowing JDK internal native library load: {}", libraryName);
      return;
    }

    String libName = libraryName != null ? libraryName : "unknown";
    dispatch(Operation.NATIVE_LOAD, libName, 0);
  }

  /**
   * Checks if the current native library load is being done by JDK internal code.
   *
   * <p>This looks at the immediate caller of System.loadLibrary (not the deep application caller)
   * to determine if the JDK itself is loading a library for its internal use.
   *
   * @return true if this is a JDK-internal library load
   */
  private static boolean isJdkInternalLibraryLoad() {
    return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
        .walk(
            frames ->
                frames
                    .skip(2) // Skip this method and onNativeLoad
                    .findFirst()
                    .map(StackWalker.StackFrame::getDeclaringClass)
                    .map(Class::getName)
                    .map(BootstrapEnforcer::isJdkInternalClass)
                    .orElse(false));
  }

  /**
   * Checks if a class name belongs to JDK internal packages.
   *
   * @param className the fully qualified class name
   * @return true if the class is JDK internal
   */
  private static boolean isJdkInternalClass(String className) {
    return className.startsWith("java.")
        || className.startsWith("javax.")
        || className.startsWith("jdk.")
        || className.startsWith("sun.")
        || className.startsWith("com.sun.");
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

  // ========== PROCESS EXECUTION ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a process execution is intercepted.
   *
   * <p>Guards {@code Runtime.exec()} and {@code ProcessBuilder.start()}.
   *
   * @param command the command being executed (first element of command array, or the command
   *     string)
   */
  public static void onProcessExec(String command) {
    dispatch(Operation.PROCESS_EXEC, command, 0);
  }

  // ========== CRYPTO PROVIDER ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a crypto provider operation is intercepted.
   *
   * <p>Guards {@code Security.addProvider()}, {@code Security.insertProviderAt()}, {@code
   * Security.removeProvider()}, and {@code Security.setProperty()}.
   */
  public static void onCryptoProvider() {
    dispatch(Operation.CRYPTO_PROVIDER, null, 0);
  }

  // ========== RUNTIME EXIT ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a JVM exit operation is intercepted.
   *
   * <p>Guards {@code System.exit()}, {@code Runtime.exit()}, and {@code Runtime.halt()}.
   *
   * @param status the exit status code
   */
  public static void onRuntimeExit(int status) {
    dispatch(Operation.RUNTIME_EXIT, status, 0);
  }

  // ========== SHUTDOWN HOOK ENTRY POINTS ==========

  /**
   * Called by ByteBuddy advice when a shutdown hook operation is intercepted.
   *
   * <p>Guards {@code Runtime.addShutdownHook()} and {@code Runtime.removeShutdownHook()}.
   */
  public static void onShutdownHook() {
    dispatch(Operation.RUNTIME_SHUTDOWN_HOOK, null, 0);
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
    CallerContext caller;
    try {
      caller = determineCallerContext();
    } catch (Exception e) {
      handleError(op, arg0, arg1, "Failed to determine caller", e);
      return;
    }

    // No application frame on the stack = JVM internal operation, allow in all modes
    if (caller == null) {
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
      SecurityException denial = cb.check(caller, op, arg0, arg1);

      if (denial != null) {
        // Always increment denial counters (all modes, zero overhead)
        DenialCounters.increment(op);

        // Describing a denial costs far more than making one: a formatted message, a record, a
        // stack and a log line. One missing entitlement on an initialisation path can be denied
        // hundreds of thousands of times a second, and that has exhausted the heap of the very
        // application jGuard was protecting. Past a threshold the enforcer stops describing --
        // never denying. The decision below is untouched and the counters above are unconditional,
        // so a storm is still fully accounted for even while it is quiet.
        //
        // The enforcer consults DenialStormGuard, not this class: by the time the callback returns,
        // the expensive part -- a SecurityException carrying a stack -- has already been built or
        // deliberately not built. It reports which by returning the shared stackless instance, so
        // the window is counted exactly once per denial rather than once on each side.
        boolean detail = !(denial instanceof SuppressedDenial);

        // Access denied
        if (mode == EnforcementMode.AUDIT) {
          if (detail) {
            // Audit mode: accumulate denials for summary at shutdown
            String args = formatArgs(op, arg0, arg1);
            DenialRecord record =
                new DenialRecord(caller.moduleName(), caller.packageName(), op, args);
            auditDenials.add(record);
            if (logDenied) {
              LOG.warn(
                  "DENIED {}: package={}, module={}, args={}",
                  op,
                  caller.packageName(),
                  caller.moduleName(),
                  args);
            }
          }
        } else if (logDenied && detail) {
          // STRICT: log at ERROR (denials are real problems, must not be missed)
          // PERMISSIVE: log at WARN
          if (mode == EnforcementMode.STRICT) {
            LOG.error(
                "DENIED {}: package={}, module={}, args={}",
                op,
                caller.packageName(),
                caller.moduleName(),
                formatArgs(op, arg0, arg1));
          } else {
            LOG.warn(
                "DENIED {}: package={}, module={}, args={}",
                op,
                caller.packageName(),
                caller.moduleName(),
                formatArgs(op, arg0, arg1));
          }
        }
        if (mode.blocksOnDenied()) {
          // A denial must never be able to take the host down, and inside a class initialiser it
          // can. Any throwable that escapes <clinit> is wrapped by the JVM as
          // ExceptionInInitializerError -- an Error, not an Exception -- so it passes every
          // catch(Exception) between here and the top of the thread, and hosts that treat Error as
          // fatal terminate. The damage outlives the throw: the class is marked erroneous for the
          // life of the JVM, so every later touch raises NoClassDefFoundError and not even a
          // hot-reloaded policy can revive it. Enforcement is recoverable by design; this is the
          // one path where it is not.
          //
          // Seen on lucenia-trial on 2026-09-18. A missing system.property.read grant for
          // java.net.useSystemProxies was denied inside sun.net.spi.DefaultProxySelector's static
          // initialiser, on the first request the AWS SDK made through HttpClient. Fifteen denials
          // killed five nodes -- the engine's memory layer, down, from one absent line of policy.
          //
          // So in initialiser context the decision is recorded and not thrown. That is a real
          // weakening and is stated plainly rather than hidden: the operation PROCEEDS where it
          // would otherwise have been blocked. It is the deliberate trade. A policy gap that
          // reaches this branch is a bug to be fixed in policy, and it is reported loudly enough to
          // find -- logged at ERROR with the initialiser named, counted separately from ordinary
          // denials, and exposed over JMX -- but a policy gap must cost a denial, never a JVM.
          // Looked for only when this denial is being described. The check is a stack question, so
          // unlike attribution it cannot be cached, and it is not cheap: attribution stops at the
          // first application frame, while this one usually matches nothing and so walks to the
          // bottom. Measured at 19,440 bytes per call against a 1,968-byte allowed call -- run
          // unconditionally it would allocate gigabytes a second under a denial storm and exhaust
          // the heap, which is the other way an enforcer kills its host and the one
          // DenialStormGuard
          // already exists to prevent. Trading one fatal failure for another is not a fix.
          //
          // Gating on detail costs no coverage where it matters. A class initialiser runs exactly
          // once, so a denial raised inside one is by construction the first denial for that class,
          // and the guard grants detail to first denials -- the fifteen that killed lucenia-trial
          // were every one of them logged in full. The residual gap is narrow and real and is not
          // papered over: if an unrelated storm on the SAME module and operation has already driven
          // the guard into suppression, an initialiser denial arriving inside that window is thrown
          // as before. Closing it needs the guard to grant detail per initialising class rather
          // than
          // per module, which is a change to DenialStormGuard and belongs in its own commit.
          StackTraceElement initializer = detail ? enclosingClassInitializer() : null;
          if (initializer != null) {
            DenialCounters.incrementInitializerUnenforced(op);
            LOG.error(
                "DENIED {} inside class initialiser {}.<clinit> -- NOT enforced: throwing here"
                    + " would escape as ExceptionInInitializerError and terminate the host."
                    + " The operation was ALLOWED. Fix the policy: package={}, module={}, args={}",
                op,
                initializer.getClassName(),
                caller.packageName(),
                caller.moduleName(),
                formatArgs(op, arg0, arg1));
          } else {
            throw denial;
          }
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
      LOG.error("{}: {} - blocking {} for {}", context, msg, op, args, e);
      throw new SecurityException("jGuard: enforcement error - " + context + ": " + msg);
    } else {
      String msg = e != null ? e.getMessage() : "unknown error";
      LOG.warn("{}: {} - allowing {} for {} (mode={})", context, msg, op, args, mode, e);
    }
  }

  // ========== CALLER ATTRIBUTION ==========

  /**
   * Determines the calling code's package and module.
   *
   * <p>Walks the stack to find the first frame that is application code (not JDK, jGuard, or
   * ByteBuddy infrastructure), then answers from a per-class cache. Both the answer and the
   * is-this-application-code test are pure functions of the class, so neither is recomputed.
   *
   * @return the caller's context, or null when no application frame is on the stack (a JVM-internal
   *     operation), which is a property of the stack and therefore not cacheable
   */
  private static CallerContext determineCallerContext() {
    ClassValue<CallerContext> contexts = callerContexts;
    ClassValue<Boolean> isApp = applicationCode;
    return WALKER.walk(
        frames ->
            frames
                .map(StackWalker.StackFrame::getDeclaringClass)
                .filter(isApp::get)
                .findFirst()
                .map(contexts::get)
                .orElse(null));
  }

  /**
   * Returns the class initialiser a throw from here would escape, or null if there is none.
   *
   * <p>Answers a question about the stack rather than about a class, so unlike attribution it
   * cannot be cached: the same method denied from a static initialiser and from ordinary code must
   * give different answers.
   *
   * <p>Deliberately conservative. A {@code <clinit>} frame anywhere below this point is treated as
   * fatal context even though an intervening frame might have caught the exception before it
   * reached the initialiser, because whether it would is not knowable from here -- and the cost of
   * being wrong is asymmetric. Guessing "not an initialiser" wrongly kills the JVM and poisons a
   * class permanently; guessing "initialiser" wrongly lets one operation through and logs it.
   *
   * <p>Expensive by nature: it short-circuits on the first initialiser frame, but the common answer
   * is "none", and reaching it means walking every frame. Callers must keep it off hot paths -- it
   * runs neither on the allow path nor on a suppressed denial, only where a denial is already being
   * described.
   *
   * @return the initialiser frame, for the log message, or null when throwing is safe
   */
  private static StackTraceElement enclosingClassInitializer() {
    return WALKER.walk(
        frames ->
            frames
                .filter(f -> "<clinit>".equals(f.getMethodName()))
                .findFirst()
                .map(StackWalker.StackFrame::toStackTraceElement)
                .orElse(null));
  }

  /** A fresh attribution cache, bound to the skip prefixes in force when it is created. */
  private static ClassValue<CallerContext> newCallerContexts() {
    return new ClassValue<>() {
      @Override
      protected CallerContext computeValue(Class<?> type) {
        Module module = type.getModule();
        String moduleName = module.isNamed() ? module.getName() : "unnamed";
        return new CallerContext(type.getPackageName(), moduleName);
      }
    };
  }

  /** A fresh application-code cache, bound to the skip prefixes in force when it is created. */
  private static ClassValue<Boolean> newApplicationCode() {
    return new ClassValue<>() {
      @Override
      protected Boolean computeValue(Class<?> type) {
        return isApplicationCode(type);
      }
    };
  }

  /**
   * Checks if a class is application code (not infrastructure).
   *
   * <p>Uses the configurable skipPrefixes to determine what to skip. Callers should go through
   * {@link #applicationCode} rather than calling this directly; it is the uncached computation
   * behind that cache.
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

}
