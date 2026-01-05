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
import org.jguard.bootstrap.CallerContext;
import org.jguard.bootstrap.Operation;
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
    indexEntitlements();
    LOG.info("PolicyEnforcer initialized for module: {}", moduleName);
  }

  /**
   * Returns the module name this enforcer is configured for.
   *
   * @return the module name
   */
  public String getModuleName() {
    return moduleName;
  }

  // ========== SINGLE DISPATCH ENTRY POINT ==========

  /**
   * Checks if the caller is entitled to perform the specified operation.
   *
   * <p>This is the single entry point for all capability checks. It handles:
   *
   * <ul>
   *   <li>Module identity verification
   *   <li>Decision caching for performance
   *   <li>Dispatch to operation-specific entitlement checking
   * </ul>
   *
   * @param context the caller context containing package and module information
   * @param op the operation being performed
   * @param arg0 primary argument (Path for fs ops, String host for net connect, null for listen)
   * @param arg1 secondary argument (0 for fs ops, port for network ops)
   * @return null if allowed, SecurityException if denied
   */
  public SecurityException check(CallerContext context, Operation op, Object arg0, int arg1) {
    String callerPackage = context.packageName();
    String callerModule = context.moduleName();

    // First, verify module identity
    if (!isValidModule(callerModule)) {
      LOG.debug("Module mismatch: caller module={}, expected module={}", callerModule, moduleName);
      return deniedModuleMismatch(callerPackage, callerModule, formatDetails(op, arg0, arg1));
    }

    // Build cache key (may be null for high-cardinality operations like HOST_PORT)
    String cacheKey = buildCacheKey(callerPackage, callerModule, op, arg0, arg1);

    // Check cache if key is available
    if (cacheKey != null) {
      Boolean cached = decisionCache.get(cacheKey);
      if (cached != null) {
        return cached
            ? null
            : denied(callerPackage, op.capabilityName(), formatDetails(op, arg0, arg1));
      }
    }

    // Check entitlements
    boolean allowed = isAllowed(callerPackage, op, arg0, arg1);

    // Cache result if key is available
    if (cacheKey != null) {
      decisionCache.put(cacheKey, allowed);
    }

    return allowed
        ? null
        : denied(callerPackage, op.capabilityName(), formatDetails(op, arg0, arg1));
  }

  // ========== CATEGORY-BASED DISPATCH ==========

  /**
   * Formats operation details for error messages.
   *
   * <p>Uses operation category - adding new operations with existing categories requires no
   * changes.
   */
  private static String formatDetails(Operation op, Object arg0, int arg1) {
    return switch (op.category()) {
      case FILESYSTEM -> arg0 != null ? arg0.toString() : "unknown path";
      case SIMPLE -> op.capabilityName();
      case PORT -> "port " + arg1;
      case TARGET_PATTERN -> arg0 != null ? arg0.toString() : "any target";
      case HOST_PORT -> {
        String host = arg0 != null ? arg0.toString() : "*";
        yield host + ":" + arg1;
      }
    };
  }

  /**
   * Builds a cache key for the given operation.
   *
   * <p>Uses operation category - adding new operations with existing categories requires no
   * changes.
   */
  private static String buildCacheKey(
      String callerPackage, String callerModule, Operation op, Object arg0, int arg1) {
    String base = callerPackage + ":" + callerModule + ":" + op.capabilityName();
    return switch (op.category()) {
      case FILESYSTEM -> base + ":" + ((Path) arg0).toAbsolutePath();
      case SIMPLE -> base;
      case PORT -> base + ":" + arg1; // Include port for caching
      case TARGET_PATTERN -> base + ":" + (arg0 != null ? arg0 : "any");
      case HOST_PORT -> null; // Don't cache HOST_PORT - high cardinality hosts
    };
  }

  /**
   * Dispatches to category-specific entitlement checking.
   *
   * <p>Uses operation category - adding new operations with existing categories requires no
   * changes.
   */
  private boolean isAllowed(String callerPackage, Operation op, Object arg0, int arg1) {
    String capability = op.capabilityName();
    return switch (op.category()) {
      case FILESYSTEM -> isAllowedFilesystem(callerPackage, (Path) arg0, capability);
      case SIMPLE -> isAllowedSimple(callerPackage, capability);
      case PORT -> isAllowedPort(callerPackage, arg1, capability);
      case TARGET_PATTERN -> isAllowedTargetPattern(callerPackage, (String) arg0, capability);
      case HOST_PORT -> isAllowedHostPort(callerPackage, (String) arg0, arg1, capability);
    };
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

  // ========== CATEGORY HANDLERS ==========

  /**
   * Handles SIMPLE category - no argument matching, just subject check.
   *
   * <p>Used for: network.outbound, threads.create, etc.
   */
  private boolean isAllowedSimple(String callerPackage, String capability) {
    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      // Simple capabilities take no arguments - if the subject matches, it's allowed
      LOG.debug("{} allowed: package={}, entitlement={}", capability, callerPackage, entitlement);
      return true;
    }

    LOG.debug("{} denied: package={}", capability, callerPackage);
    return false;
  }

  /**
   * Handles PORT category - optional port or port-range restriction.
   *
   * <p>Used for: network.listen
   *
   * <p>Port 0 (ephemeral) is only allowed if the entitlement explicitly includes it.
   */
  private boolean isAllowedPort(String callerPackage, int port, String capability) {
    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      List<CapabilityArgument> args = entitlement.capability().arguments();
      if (args.isEmpty()) {
        // No arguments - allows any port (including port 0)
        LOG.debug(
            "{} allowed (any port): package={}, port={}, entitlement={}",
            capability,
            callerPackage,
            port,
            entitlement);
        return true;
      } else if (args.size() == 1) {
        // Port or port-range restriction
        PortRange range = parsePortArg(args.get(0));
        if (range.contains(port)) {
          LOG.debug(
              "{} allowed (port match): package={}, port={}, range={}, entitlement={}",
              capability,
              callerPackage,
              port,
              range,
              entitlement);
          return true;
        }
      }
    }

    LOG.debug("{} denied: package={}, port={}", capability, callerPackage, port);
    return false;
  }

  /**
   * Handles HOST_PORT category - host glob + port/port-range filtering.
   *
   * <p>Used for: network.outbound
   *
   * <p>Port 0 is not a valid destination for outbound connections and is always denied.
   */
  private boolean isAllowedHostPort(
      String callerPackage, String host, int port, String capability) {
    // Port 0 is not a valid destination for outbound connections
    if (port == 0) {
      LOG.debug("{} denied: port 0 is invalid destination", capability);
      return false;
    }

    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      List<CapabilityArgument> args = entitlement.capability().arguments();

      if (args.isEmpty()) {
        // No args = any host, any port
        LOG.debug(
            "{} allowed (any host/port): package={}, host={}, port={}, entitlement={}",
            capability,
            callerPackage,
            host,
            port,
            entitlement);
        return true;
      }

      String hostPattern = "*";
      PortRange portRange = PortRange.any();

      if (args.size() >= 1) {
        hostPattern = getStringArg(args.get(0));
      }
      if (args.size() >= 2) {
        portRange = parsePortArg(args.get(1));
      }

      if (HostMatcher.matches(host, hostPattern) && portRange.contains(port)) {
        LOG.debug(
            "{} allowed: package={}, host={}, port={}, hostPattern={}, portRange={}, entitlement={}",
            capability,
            callerPackage,
            host,
            port,
            hostPattern,
            portRange,
            entitlement);
        return true;
      }
    }

    LOG.debug("{} denied: package={}, host={}, port={}", capability, callerPackage, host, port);
    return false;
  }

  private PortRange parsePortArg(CapabilityArgument arg) {
    if (arg instanceof CapabilityArgument.IntegerArg intArg) {
      return PortRange.single((int) intArg.value());
    } else if (arg instanceof CapabilityArgument.StringArg strArg) {
      return PortRange.parse(strArg.value());
    }
    throw new IllegalArgumentException("Invalid port argument: " + arg);
  }

  private String getStringArg(CapabilityArgument arg) {
    if (arg instanceof CapabilityArgument.StringArg strArg) {
      return strArg.value();
    } else if (arg instanceof CapabilityArgument.IntegerArg) {
      throw new IllegalArgumentException("Expected string argument, got integer: " + arg);
    }
    throw new IllegalArgumentException("Invalid argument: " + arg);
  }

  /**
   * Handles TARGET_PATTERN category - optional pattern restriction.
   *
   * <p>Used for: native.load, env.read, system.property.read/write, etc.
   *
   * <h2>Bulk Access</h2>
   *
   * <p>When {@code target} is null, it indicates bulk access (e.g., {@code System.getenv()}, {@code
   * System.getProperties()}). Bulk access requires either:
   *
   * <ul>
   *   <li>No-arg entitlement (e.g., {@code env.read}) - grants access to all targets
   *   <li>Wildcard pattern (e.g., {@code env.read("*")}) - explicit wildcard
   * </ul>
   *
   * <p>Specific pattern entitlements like {@code env.read("HOME")} do NOT grant bulk access.
   */
  private boolean isAllowedTargetPattern(String callerPackage, String target, String capability) {
    boolean isBulkAccess = (target == null);

    for (Entitlement entitlement : policy.entitlements()) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage)) {
        continue;
      }

      List<CapabilityArgument> args = entitlement.capability().arguments();
      if (args.isEmpty()) {
        // No arguments - allows any target (including bulk access)
        LOG.debug(
            "{} allowed (any target): package={}, target={}, entitlement={}",
            capability,
            callerPackage,
            target != null ? target : "bulk",
            entitlement);
        return true;
      } else if (args.size() == 1) {
        String pattern = ((CapabilityArgument.StringArg) args.get(0)).value();

        // For bulk access, only no-arg or "*" pattern grants access
        if (isBulkAccess) {
          if ("*".equals(pattern)) {
            LOG.debug(
                "{} allowed (bulk, wildcard): package={}, entitlement={}",
                capability,
                callerPackage,
                entitlement);
            return true;
          }
          // Continue checking other entitlements - a specific pattern doesn't grant bulk access
          continue;
        }

        // Pattern restriction - match target against pattern
        if (targetMatchesPattern(target, pattern)) {
          LOG.debug(
              "{} allowed (pattern match): package={}, target={}, pattern={}, entitlement={}",
              capability,
              callerPackage,
              target,
              pattern,
              entitlement);
          return true;
        }
      }
    }

    LOG.debug(
        "{} denied: package={}, target={}",
        capability,
        callerPackage,
        target != null ? target : "bulk");
    return false;
  }

  /**
   * Matches a target (env var name, property key, library path, etc.) against a pattern.
   *
   * <p>Pattern syntax:
   *
   * <ul>
   *   <li>{@code *} - matches any target
   *   <li>{@code HOME} - exact match for simple names (env vars, properties)
   *   <li>{@code com.example.Foo} - exact match for dotted names
   *   <li>{@code com.example.*} - matches direct children (com.example.Foo, not
   *       com.example.sub.Bar)
   *   <li>{@code com.example.**} - matches all descendants
   * </ul>
   */
  private boolean targetMatchesPattern(String target, String pattern) {
    if (target == null) {
      return false;
    }
    // Wildcard matches any non-null target
    if ("*".equals(pattern)) {
      return true;
    }
    if (pattern.endsWith(".**")) {
      String prefix = pattern.substring(0, pattern.length() - 3);
      return target.equals(prefix) || target.startsWith(prefix + ".");
    } else if (pattern.endsWith(".*")) {
      String prefix = pattern.substring(0, pattern.length() - 2);
      if (!target.startsWith(prefix + ".")) {
        return false;
      }
      // Check there's exactly one more segment (no more dots after prefix)
      String remainder = target.substring(prefix.length() + 1);
      return !remainder.contains(".");
    } else {
      return target.equals(pattern);
    }
  }

  /**
   * Handles FILESYSTEM category - root + glob matching.
   *
   * <p>Used for: fs.read, fs.write
   */
  private boolean isAllowedFilesystem(String callerPackage, Path path, String capability) {
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

  private void indexEntitlements() {
    for (Entitlement entitlement : policy.entitlements()) {
      LOG.debug("Indexed entitlement: {}", entitlement);
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
