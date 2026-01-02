/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jguard.bootstrap.AgentConfig;
import org.jguard.bootstrap.AgentLogger;
import org.jguard.bootstrap.BootstrapEnforcer.CallerContext;
import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;

/**
 * Enforces policy decisions for capability checks.
 *
 * <p>This class is the core decision engine for jGuard. It determines whether a given package is
 * entitled to perform a specific operation based on the loaded policy.
 *
 * <p>Thread-safe. Decisions are cached for performance.
 */
public final class PolicyEnforcer {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyEnforcer.class);

  private final PolicyDescriptor policy;
  private final String moduleName;
  private final AgentConfig config;

  // Cache: "package:capability:args" -> allowed
  private final Map<String, Boolean> decisionCache = new ConcurrentHashMap<>();

  PolicyEnforcer(PolicyDescriptor policy, AgentConfig config) {
    this.policy = policy;
    this.moduleName = policy.moduleName();
    this.config = config;
    indexFsEntitlements();
    LOG.info("PolicyEnforcer initialized for module: {}", moduleName);
  }

  /**
   * Checks if the caller is entitled to read the specified path.
   *
   * <p>This method verifies both the package and module of the caller against the policy. A caller
   * is only allowed if:
   *
   * <ul>
   *   <li>The caller's module matches the policy's expected module, OR
   *   <li>The caller is in an unnamed module (classpath) and the policy allows unnamed modules
   *   <li>AND the caller's package matches an entitlement for the requested path
   * </ul>
   *
   * @param context the caller context containing package and module information
   * @param path the path being accessed
   * @return null if allowed, SecurityException if denied
   */
  public SecurityException checkFsReadReturningException(CallerContext context, Path path) {
    String callerPackage = context.packageName();
    String callerModule = context.moduleName();

    // First, verify module identity
    if (!isValidModule(callerModule)) {
      LOG.debug("Module mismatch: caller module={}, expected module={}", callerModule, moduleName);
      return deniedModuleMismatch(callerPackage, callerModule, path.toString());
    }

    String cacheKey = callerPackage + ":" + callerModule + ":fs.read:" + path.toAbsolutePath();
    Boolean cached = decisionCache.get(cacheKey);
    if (cached != null) {
      return cached ? null : denied(callerPackage, "fs.read", path.toString());
    }

    boolean allowed = isAllowedFsRead(callerPackage, path);
    decisionCache.put(cacheKey, allowed);

    return allowed ? null : denied(callerPackage, "fs.read", path.toString());
  }

  /**
   * Checks if the caller is entitled to read the specified path. Throws if denied.
   *
   * @param context the caller context containing package and module information
   * @param path the path being accessed
   * @throws SecurityException if access is denied
   */
  public void checkFsRead(CallerContext context, Path path) {
    SecurityException denial = checkFsReadReturningException(context, path);
    if (denial != null) {
      throw denial;
    }
  }

  /**
   * Checks if the caller is entitled to write to the specified path.
   *
   * @param context the caller context containing package and module information
   * @param path the path being written
   * @return null if allowed, SecurityException if denied
   */
  public SecurityException checkFsWriteReturningException(CallerContext context, Path path) {
    String callerPackage = context.packageName();
    String callerModule = context.moduleName();

    // First, verify module identity
    if (!isValidModule(callerModule)) {
      LOG.debug("Module mismatch: caller module={}, expected module={}", callerModule, moduleName);
      return deniedModuleMismatch(callerPackage, callerModule, path.toString());
    }

    String cacheKey = callerPackage + ":" + callerModule + ":fs.write:" + path.toAbsolutePath();
    Boolean cached = decisionCache.get(cacheKey);
    if (cached != null) {
      return cached ? null : denied(callerPackage, "fs.write", path.toString());
    }

    boolean allowed = isAllowedFsWrite(callerPackage, path);
    decisionCache.put(cacheKey, allowed);

    return allowed ? null : denied(callerPackage, "fs.write", path.toString());
  }

  /**
   * Checks if the caller is entitled to write to the specified path. Throws if denied.
   *
   * @param context the caller context containing package and module information
   * @param path the path being written
   * @throws SecurityException if access is denied
   */
  public void checkFsWrite(CallerContext context, Path path) {
    SecurityException denial = checkFsWriteReturningException(context, path);
    if (denial != null) {
      throw denial;
    }
  }

  /**
   * Checks if the caller is entitled to make outbound network connections.
   *
   * @param context the caller context containing package and module information
   * @return null if allowed, SecurityException if denied
   */
  public SecurityException checkNetworkOutboundReturningException(CallerContext context) {
    String callerPackage = context.packageName();
    String callerModule = context.moduleName();

    // First, verify module identity
    if (!isValidModule(callerModule)) {
      LOG.debug("Module mismatch: caller module={}, expected module={}", callerModule, moduleName);
      return deniedModuleMismatch(callerPackage, callerModule, "network.outbound");
    }

    String cacheKey = callerPackage + ":" + callerModule + ":network.outbound";
    Boolean cached = decisionCache.get(cacheKey);
    if (cached != null) {
      return cached ? null : denied(callerPackage, "network.outbound", "outbound connection");
    }

    boolean allowed = isAllowedNetworkOutbound(callerPackage);
    decisionCache.put(cacheKey, allowed);

    return allowed ? null : denied(callerPackage, "network.outbound", "outbound connection");
  }

  /**
   * Checks if the caller is entitled to make outbound network connections. Throws if denied.
   *
   * @param context the caller context containing package and module information
   * @throws SecurityException if access is denied
   */
  public void checkNetworkOutbound(CallerContext context) {
    SecurityException denial = checkNetworkOutboundReturningException(context);
    if (denial != null) {
      throw denial;
    }
  }

  /**
   * Checks if the caller is entitled to listen on a server socket.
   *
   * @param context the caller context containing package and module information
   * @param port the port being bound to
   * @return null if allowed, SecurityException if denied
   */
  public SecurityException checkNetworkListenReturningException(CallerContext context, int port) {
    String callerPackage = context.packageName();
    String callerModule = context.moduleName();

    // First, verify module identity
    if (!isValidModule(callerModule)) {
      LOG.debug("Module mismatch: caller module={}, expected module={}", callerModule, moduleName);
      return deniedModuleMismatch(callerPackage, callerModule, "network.listen");
    }

    String cacheKey = callerPackage + ":" + callerModule + ":network.listen:" + port;
    Boolean cached = decisionCache.get(cacheKey);
    if (cached != null) {
      return cached ? null : denied(callerPackage, "network.listen", "port " + port);
    }

    boolean allowed = isAllowedNetworkListen(callerPackage, port);
    decisionCache.put(cacheKey, allowed);

    return allowed ? null : denied(callerPackage, "network.listen", "port " + port);
  }

  /**
   * Checks if the caller is entitled to listen on a server socket. Throws if denied.
   *
   * @param context the caller context containing package and module information
   * @param port the port being bound to
   * @throws SecurityException if access is denied
   */
  public void checkNetworkListen(CallerContext context, int port) {
    SecurityException denial = checkNetworkListenReturningException(context, port);
    if (denial != null) {
      throw denial;
    }
  }

  /**
   * Validates that the caller's module is allowed by the policy.
   *
   * <p>The policy is compiled for a specific module. We allow:
   *
   * <ul>
   *   <li>Exact module match
   *   <li>Unnamed modules (classpath) - these are common for tests and simple apps
   * </ul>
   */
  private boolean isValidModule(String callerModule) {
    // Exact match with policy module
    if (callerModule.equals(moduleName)) {
      return true;
    }

    // Allow unnamed modules (classpath code) - the package-level check will still apply
    // This is necessary for:
    // - Tests running without module-path
    // - Simple applications not using JPMS
    // - Libraries loaded via classpath
    if ("unnamed".equals(callerModule)) {
      LOG.debug("Allowing unnamed module - package-level check will apply");
      return true;
    }

    return false;
  }

  private boolean isAllowedFsRead(String callerPackage, Path path) {
    return isAllowedFsOperation(callerPackage, path, "fs.read");
  }

  private boolean isAllowedFsWrite(String callerPackage, Path path) {
    return isAllowedFsOperation(callerPackage, path, "fs.write");
  }

  private boolean isAllowedNetworkOutbound(String callerPackage) {
    // Check all entitlements that apply to this caller
    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals("network.outbound")) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      // network.outbound takes no arguments - if the subject matches, it's allowed
      LOG.debug("network.outbound allowed: package={}, entitlement={}", callerPackage, entitlement);
      return true;
    }

    LOG.debug("network.outbound denied: package={}", callerPackage);
    return false;
  }

  private boolean isAllowedNetworkListen(String callerPackage, int port) {
    // Check all entitlements that apply to this caller
    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals("network.listen")) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      List<CapabilityArgument> args = entitlement.capability().arguments();
      if (args.isEmpty()) {
        // network.listen with no arguments - allows any port
        LOG.debug(
            "network.listen allowed (any port): package={}, port={}, entitlement={}",
            callerPackage,
            port,
            entitlement);
        return true;
      } else if (args.size() == 1) {
        // network.listen(port) - check specific port
        long allowedPort = ((CapabilityArgument.IntegerArg) args.get(0)).value();
        if (port == allowedPort || port == 0) {
          // Port 0 means "any available port" - we allow it if they have any listen entitlement
          LOG.debug(
              "network.listen allowed (port match): package={}, port={}, entitlement={}",
              callerPackage,
              port,
              entitlement);
          return true;
        }
      }
    }

    LOG.debug("network.listen denied: package={}, port={}", callerPackage, port);
    return false;
  }

  private boolean isAllowedFsOperation(String callerPackage, Path path, String capability) {
    Path absPath = path.toAbsolutePath().normalize();

    // Check all entitlements that apply to this caller
    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      // Check if path matches the entitlement's root/glob
      List<CapabilityArgument> args = entitlement.capability().arguments();
      if (args.size() == 2) {
        String root = ((CapabilityArgument.StringArg) args.get(0)).value();
        String glob = ((CapabilityArgument.StringArg) args.get(1)).value();

        if (pathMatches(absPath, root, glob)) {
          LOG.debug(
              "{} allowed: package={}, path={}, entitlement={}",
              capability,
              callerPackage,
              absPath,
              entitlement);
          return true;
        }
      }
    }

    LOG.debug("{} denied: package={}, path={}", capability, callerPackage, absPath);
    return false;
  }

  private boolean subjectMatches(SubjectPattern subject, String callerPackage) {
    return switch (subject.type()) {
      case MODULE ->
          // Module-wide grant: matches any package in this module
          callerPackage.startsWith(moduleName);
      case PACKAGE_EXACT ->
          // Exact package match
          callerPackage.equals(subject.packageName());
      case PACKAGE_DIRECT_CHILDREN ->
          // Direct children: package must be an immediate child
          isDirectChild(subject.packageName(), callerPackage);
      case PACKAGE_RECURSIVE ->
          // Recursive: package must be the subject or a descendant
          callerPackage.equals(subject.packageName())
              || callerPackage.startsWith(subject.packageName() + ".");
    };
  }

  private boolean isDirectChild(String parent, String child) {
    if (!child.startsWith(parent + ".")) {
      return false;
    }
    // Check there's exactly one more segment
    String remainder = child.substring(parent.length() + 1);
    return !remainder.contains(".");
  }

  private boolean pathMatches(Path absPath, String root, String glob) {
    // Normalize the root path - if it's absolute, use as-is; otherwise treat as absolute
    Path rootPath = Path.of(root);
    if (!rootPath.isAbsolute()) {
      rootPath = rootPath.toAbsolutePath();
    }
    rootPath = rootPath.normalize();

    // Path must be under root
    if (!absPath.startsWith(rootPath)) {
      return false;
    }

    // Get the relative path from root to the target
    Path relativePath = rootPath.relativize(absPath);

    // Apply glob pattern to the relative path
    // Note: In glob syntax, "/" matches the platform path separator automatically
    // Do NOT convert "/" to "\" on Windows - backslash is an escape character in glob!
    PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + glob);
    return matcher.matches(relativePath);
  }

  private void indexFsEntitlements() {
    for (Entitlement entitlement : policy.entitlements()) {
      String capName = entitlement.capability().name();
      if (capName.equals("fs.read")
          || capName.equals("fs.write")
          || capName.equals("network.outbound")
          || capName.equals("network.listen")) {
        LOG.debug("Indexed {} entitlement: {}", capName, entitlement);
      }
    }
  }

  private SecurityException denied(String callerPackage, String capability, String details) {
    String message =
        String.format(
            "jGuard: access denied - package '%s' is not entitled to '%s' (%s)",
            callerPackage, capability, details);
    return new SecurityException(message);
  }

  private SecurityException deniedModuleMismatch(
      String callerPackage, String callerModule, String details) {
    String message =
        String.format(
            "jGuard: access denied - module '%s' does not match policy module '%s' "
                + "(package='%s', path=%s)",
            callerModule, moduleName, callerPackage, details);
    return new SecurityException(message);
  }
}
