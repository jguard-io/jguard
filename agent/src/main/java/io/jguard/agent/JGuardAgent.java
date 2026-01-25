/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.Version;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.jar.JarFile;

/**
 * jGuard Java agent entry point.
 *
 * <p>This agent enforces capability-based security policies by instrumenting JDK classes to check
 * entitlements before sensitive operations.
 *
 * <p><b>IMPORTANT:</b> This class must NOT import any types from io.jguard.bootstrap.* because
 * those types are not available until after bootstrap injection. All bootstrap-dependent logic is
 * in {@link AgentInitializer}, which is loaded via reflection after injection.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * java -javaagent:jguard-agent.jar=policy.bin -jar myapp.jar
 * }</pre>
 *
 * <h2>Agent Arguments</h2>
 *
 * <p>The agent accepts the path to a compiled policy file (.bin) as its argument.
 *
 * <h2>System Properties</h2>
 *
 * <ul>
 *   <li>{@code jguard.policy} - Path to policy file (alternative to agent argument)
 *   <li>{@code jguard.mode} - Enforcement mode: strict, permissive, or audit
 *   <li>{@code jguard.log.level} - Log level: error, warn, info, debug, trace
 *   <li>{@code jguard.log.denied} - Log denied operations (default: true)
 *   <li>{@code jguard.log.allowed} - Log allowed operations (default: false)
 * </ul>
 *
 * <h2>Two-Phase Initialization</h2>
 *
 * <p>The agent uses two-phase initialization to solve the classloader chicken-and-egg problem:
 *
 * <ol>
 *   <li>JGuardAgent.premain() injects bootstrap.jar into the bootstrap classloader
 *   <li>AgentInitializer.initialize() is called via reflection (can now use bootstrap types)
 * </ol>
 *
 * <p>This separation is necessary because JVM class loading resolves all imported types when a
 * class is loaded. If JGuardAgent imported bootstrap types directly, the JVM would try to resolve
 * them before premain() runs, causing NoClassDefFoundError.
 */
public final class JGuardAgent {

  /** Resource path for the embedded bootstrap JAR. */
  private static final String BOOTSTRAP_JAR_RESOURCE = "/jguard/bootstrap.jar";

  private JGuardAgent() {
    // Entry point class
  }

  /**
   * Agent premain entry point.
   *
   * @param agentArgs the path to the policy file
   * @param inst the instrumentation instance
   */
  public static void premain(String agentArgs, Instrumentation inst) {
    try {
      // Phase 1: Inject bootstrap classes FIRST - before anything that uses them
      injectBootstrapClasses(inst);

      // Phase 2: Call AgentInitializer via reflection (it can now use bootstrap types)
      initializeAgent(agentArgs, inst);

    } catch (Exception e) {
      // Can't use AgentLogger here - bootstrap may not be loaded
      System.err.println("[jGuard] FATAL: Agent initialization failed: " + e.getMessage());
      e.printStackTrace(System.err);

      // Check if we should fail hard or continue
      String mode = System.getProperty("jguard.mode", "strict");
      if ("strict".equalsIgnoreCase(mode)) {
        throw new RuntimeException("jGuard agent initialization failed", e);
      } else {
        System.err.println("[jGuard] Continuing without enforcement (mode=" + mode + ")");
      }
    }
  }

  /**
   * Agent agentmain entry point (for dynamic attach).
   *
   * @param agentArgs the path to the policy file
   * @param inst the instrumentation instance
   */
  public static void agentmain(String agentArgs, Instrumentation inst) {
    premain(agentArgs, inst);
  }

  /**
   * Injects bootstrap classes into the bootstrap classloader.
   *
   * <p>This uses the production-grade approach: extract the embedded bootstrap JAR and use {@link
   * Instrumentation#appendToBootstrapClassLoaderSearch(JarFile)} to add it to the bootstrap
   * classpath.
   */
  private static void injectBootstrapClasses(Instrumentation inst) throws IOException {
    // Extract embedded bootstrap JAR to temp file
    File bootstrapJar = extractBootstrapJar();

    // Add to bootstrap classloader search path
    inst.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar));
  }

  /**
   * Extracts the embedded bootstrap JAR from the agent JAR to a cached file.
   *
   * <p>The bootstrap JAR is cached by version in a user-specific cache directory to avoid creating
   * duplicate temp files when multiple JVMs use the same jGuard version. This is particularly
   * beneficial in test environments where many JVMs may be spawned.
   *
   * <p><b>Security:</b> The cache directory is user-specific and protected from symlink attacks:
   *
   * <ul>
   *   <li>Cache location: ~/.cache/jguard/ (or user-specific temp dir on Windows)
   *   <li>On POSIX systems: validates file ownership matches current user
   *   <li>On POSIX systems: validates file is not world-writable
   *   <li>Falls back to per-JVM temp file if validation fails
   * </ul>
   *
   * @return the path to the extracted JAR file
   * @throws IOException if extraction fails
   */
  private static File extractBootstrapJar() throws IOException {
    // Try cached approach first, fall back to temp file if any issues
    try {
      return extractBootstrapJarCached();
    } catch (IOException e) {
      // Cache approach failed, fall back to per-JVM temp file
      return extractToTempFile();
    }
  }

  /**
   * Attempts to extract bootstrap JAR using the cache mechanism.
   *
   * @return the path to the extracted JAR file
   * @throws IOException if caching fails (caller should fall back to temp file)
   */
  private static File extractBootstrapJarCached() throws IOException {
    // Use user-specific cache directory to prevent attacks via shared temp
    Path cacheDir = getUserCacheDir();
    Path cachedJar = cacheDir.resolve(getCacheFileName());

    // Try to use cached version if it exists and passes security checks
    if (Files.exists(cachedJar) && isSecureAndValidJar(cachedJar)) {
      return cachedJar.toFile();
    }

    // Ensure cache directory exists with secure permissions
    if (!Files.exists(cacheDir)) {
      Files.createDirectories(cacheDir);
      setSecurePermissions(cacheDir);
    }

    // Extract to a temp file first, then atomically move to cache location
    try (InputStream is = JGuardAgent.class.getResourceAsStream(BOOTSTRAP_JAR_RESOURCE)) {
      if (is == null) {
        throw new IOException(
            "Bootstrap JAR not found in agent: "
                + BOOTSTRAP_JAR_RESOURCE
                + ". The agent JAR may be corrupted or built incorrectly.");
      }

      // Create temp file in same directory for atomic move
      Path tempJar = Files.createTempFile(cacheDir, "jguard-bootstrap-", ".jar.tmp");

      try {
        // Copy resource to temp file
        Files.copy(is, tempJar, StandardCopyOption.REPLACE_EXISTING);

        // Set secure permissions before moving
        setSecurePermissions(tempJar);

        // Atomically move to cache location (handles concurrent JVM startup)
        try {
          Files.move(tempJar, cachedJar, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
          // Fall back to non-atomic move if atomic not supported
          Files.move(tempJar, cachedJar, StandardCopyOption.REPLACE_EXISTING);
        }

        return cachedJar.toFile();
      } catch (IOException e) {
        // If move fails (e.g., another JVM won the race), try to use the cached file
        Files.deleteIfExists(tempJar);
        if (Files.exists(cachedJar) && isSecureAndValidJar(cachedJar)) {
          return cachedJar.toFile();
        }
        // Re-throw to trigger fallback to temp file
        throw e;
      }
    }
  }

  /** System property to override the bootstrap cache directory. */
  static final String CACHE_DIR_PROPERTY = "jguard.bootstrap.cache.dir";

  /**
   * Returns the cache directory for jGuard bootstrap JAR.
   *
   * <p>The directory can be configured via the {@code jguard.bootstrap.cache.dir} system property.
   * If not set, defaults to a user-specific location:
   *
   * <ul>
   *   <li>Unix-like: ~/.cache/jguard/ (or $XDG_CACHE_HOME/jguard)
   *   <li>Windows: %LOCALAPPDATA%/jguard/cache (or %TEMP%/jguard-{username})
   * </ul>
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * # Test environments (cleanup with test artifacts)
   * -Djguard.bootstrap.cache.dir=build/testrun/cluster1/jguard-cache
   *
   * # Production environments
   * -Djguard.bootstrap.cache.dir=/var/cache/jguard
   * }</pre>
   *
   * @return the cache directory path
   */
  static Path getUserCacheDir() {
    // Allow override via system property (useful for test and production environments)
    String override = System.getProperty(CACHE_DIR_PROPERTY);
    if (override != null && !override.isEmpty()) {
      return Path.of(override);
    }

    String os = System.getProperty("os.name", "").toLowerCase();
    if (os.contains("win")) {
      // Windows: use LOCALAPPDATA or fall back to temp with username
      String localAppData = System.getenv("LOCALAPPDATA");
      if (localAppData != null) {
        return Path.of(localAppData, "jguard", "cache");
      }
      return Path.of(
          System.getProperty("java.io.tmpdir"), "jguard-" + System.getProperty("user.name"));
    } else {
      // Unix-like: use XDG_CACHE_HOME or ~/.cache
      String xdgCache = System.getenv("XDG_CACHE_HOME");
      if (xdgCache != null) {
        return Path.of(xdgCache, "jguard");
      }
      return Path.of(System.getProperty("user.home"), ".cache", "jguard");
    }
  }

  /**
   * Returns the cache file name for the current jGuard version.
   *
   * @return cache file name like "jguard-bootstrap-0.3.0.jar"
   */
  static String getCacheFileName() {
    return "jguard-bootstrap-" + Version.VERSION + ".jar";
  }

  /**
   * Checks if a cached file is secure (owned by current user, not world-writable) and a valid JAR.
   *
   * @param path the path to check
   * @return true if the file passes security checks and is a valid JAR
   */
  static boolean isSecureAndValidJar(Path path) {
    // First check if it's a valid JAR
    if (!isValidJarFile(path)) {
      return false;
    }

    // Security check: must not be a symlink
    if (Files.isSymbolicLink(path)) {
      return false;
    }

    // On POSIX systems, validate ownership and permissions
    PosixFileAttributeView posixView =
        Files.getFileAttributeView(path, PosixFileAttributeView.class);
    if (posixView != null) {
      try {
        PosixFileAttributes attrs = posixView.readAttributes();

        // Must be owned by current user
        String currentUser = System.getProperty("user.name");
        String fileOwner = attrs.owner().getName();
        if (!currentUser.equals(fileOwner)) {
          return false;
        }

        // Must not be world-writable
        Set<PosixFilePermission> perms = attrs.permissions();
        if (perms.contains(PosixFilePermission.OTHERS_WRITE)) {
          return false;
        }
      } catch (IOException e) {
        // If we can't read attributes, consider it insecure
        return false;
      }
    }

    return true;
  }

  /**
   * Checks if a file is a valid JAR file by attempting to open it.
   *
   * @param path the path to check
   * @return true if the file is a valid JAR
   */
  static boolean isValidJarFile(Path path) {
    try {
      new JarFile(path.toFile()).close();
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  /**
   * Sets secure permissions on a file or directory (owner read/write only on POSIX systems).
   *
   * @param path the path to secure
   */
  static void setSecurePermissions(Path path) {
    PosixFileAttributeView posixView =
        Files.getFileAttributeView(path, PosixFileAttributeView.class);
    if (posixView != null) {
      try {
        Set<PosixFilePermission> perms;
        if (Files.isDirectory(path)) {
          // rwx------ for directories
          perms =
              Set.of(
                  PosixFilePermission.OWNER_READ,
                  PosixFilePermission.OWNER_WRITE,
                  PosixFilePermission.OWNER_EXECUTE);
        } else {
          // rw------- for files
          perms = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        }
        posixView.setPermissions(perms);
      } catch (IOException e) {
        // Best effort - continue even if we can't set permissions
      }
    }
  }

  /**
   * Fallback: extracts bootstrap JAR to a per-JVM temp file.
   *
   * @return the path to the extracted JAR file
   * @throws IOException if extraction fails
   */
  private static File extractToTempFile() throws IOException {
    try (InputStream is = JGuardAgent.class.getResourceAsStream(BOOTSTRAP_JAR_RESOURCE)) {
      if (is == null) {
        throw new IOException(
            "Bootstrap JAR not found in agent: "
                + BOOTSTRAP_JAR_RESOURCE
                + ". The agent JAR may be corrupted or built incorrectly.");
      }

      Path tempJar = Files.createTempFile("jguard-bootstrap-", ".jar");
      File tempFile = tempJar.toFile();
      tempFile.deleteOnExit();

      Files.copy(is, tempJar, StandardCopyOption.REPLACE_EXISTING);

      return tempFile;
    }
  }

  /**
   * Initializes the agent via reflection.
   *
   * <p>This method uses reflection to call AgentInitializer.initialize() because:
   *
   * <ul>
   *   <li>AgentInitializer imports bootstrap types
   *   <li>Those types are now available (after injectBootstrapClasses)
   *   <li>Using reflection defers class loading until this method runs
   * </ul>
   */
  private static void initializeAgent(String agentArgs, Instrumentation inst) throws Exception {
    Class<?> initClass = Class.forName("io.jguard.agent.AgentInitializer");
    Method initMethod = initClass.getMethod("initialize", String.class, Instrumentation.class);
    initMethod.invoke(null, agentArgs, inst);
  }
}
