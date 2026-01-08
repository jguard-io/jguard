/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.AgentLogger;
import io.jguard.bootstrap.CallerContext;
import io.jguard.bootstrap.Operation;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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

  private final ApplicationPolicy policy;
  private final AgentConfig config;

  // Cache: "module:package:capability:args" -> allowed
  private final Map<String, Boolean> decisionCache = new ConcurrentHashMap<>();

  /**
   * Creates a PolicyEnforcer for a multi-module application policy.
   *
   * @param policy the application policy containing all module policies
   * @param config the agent configuration
   */
  PolicyEnforcer(ApplicationPolicy policy, AgentConfig config) {
    this.policy = policy;
    this.config = config;
    indexEntitlements();
    LOG.info(
        "PolicyEnforcer initialized for {} module(s): {}",
        policy.modules().size(),
        policy.modules().stream().map(ModulePolicy::moduleName).toList());
  }

  /**
   * Creates a PolicyEnforcer from a legacy single-module PolicyDescriptor.
   *
   * @param descriptor the legacy policy descriptor
   * @param config the agent configuration
   */
  PolicyEnforcer(PolicyDescriptor descriptor, AgentConfig config) {
    this(ApplicationPolicy.fromDescriptor(descriptor), config);
  }

  /**
   * Returns the module name this enforcer is configured for.
   *
   * <p>For multi-module policies, returns the first module name (for backward compatibility).
   * Prefer using {@link #getModuleNames()} for multi-module policies.
   *
   * @return the first module name, or "none" if no modules
   */
  public String getModuleName() {
    return policy.modules().isEmpty() ? "none" : policy.modules().get(0).moduleName();
  }

  /**
   * Returns all module names this enforcer has policies for.
   *
   * @return list of module names
   */
  public List<String> getModuleNames() {
    return policy.modules().stream().map(ModulePolicy::moduleName).toList();
  }

  /**
   * Checks if this enforcer has a policy for the given module.
   *
   * @param moduleName the module name to check
   * @return true if a policy exists for the module
   */
  public boolean hasModule(String moduleName) {
    return policy.hasModule(moduleName);
  }

  // ========== SINGLE DISPATCH ENTRY POINT ==========

  /**
   * Checks if the caller is entitled to perform the specified operation.
   *
   * <p>This is the single entry point for all capability checks. It handles:
   *
   * <ul>
   *   <li>Module identity verification (caller must have a policy)
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

    // Look up the policy for this module
    Optional<ModulePolicy> modulePolicy = getModulePolicy(callerModule);
    if (modulePolicy.isEmpty()) {
      LOG.debug("No policy for module: {}", callerModule);
      return deniedNoPolicy(callerPackage, callerModule, formatDetails(op, arg0, arg1));
    }

    List<Entitlement> entitlements = modulePolicy.get().entitlements();
    String moduleName = modulePolicy.get().moduleName();

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

    // Check entitlements for this module
    boolean allowed = isAllowed(callerPackage, moduleName, entitlements, op, arg0, arg1);

    // Cache result if key is available
    if (cacheKey != null) {
      decisionCache.put(cacheKey, allowed);
    }

    return allowed
        ? null
        : denied(callerPackage, op.capabilityName(), formatDetails(op, arg0, arg1));
  }

  /**
   * Gets the module policy for a caller's module.
   *
   * <p>Handles special cases:
   *
   * <ul>
   *   <li>Named JPMS modules: exact match by module name
   *   <li>Unnamed module (classpath): For backward compatibility with single-module apps, unnamed
   *       callers use the single policy if there's only one module. For multi-module apps, unnamed
   *       callers need an explicit "unnamed" policy.
   * </ul>
   */
  private Optional<ModulePolicy> getModulePolicy(String callerModule) {
    // First try exact match
    Optional<ModulePolicy> exact = policy.getModule(callerModule);
    if (exact.isPresent()) {
      return exact;
    }

    // For unnamed modules (classpath code)
    if ("unnamed".equals(callerModule)) {
      // Check for explicit "unnamed" policy first
      Optional<ModulePolicy> unnamed = policy.getModule(ApplicationPolicy.UNNAMED_MODULE);
      if (unnamed.isPresent()) {
        return unnamed;
      }

      // Backward compatibility: if there's only one module policy, use it for unnamed callers.
      // This supports existing single-module apps where tests run on classpath.
      if (policy.modules().size() == 1) {
        LOG.debug(
            "Allowing unnamed module to use single-module policy: {}",
            policy.modules().get(0).moduleName());
        return Optional.of(policy.modules().get(0));
      }
    }

    return Optional.empty();
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
   *
   * @param callerPackage the calling package name
   * @param moduleName the module name (for subject matching)
   * @param entitlements the entitlements for this module
   * @param op the operation being checked
   * @param arg0 primary argument
   * @param arg1 secondary argument
   * @return true if allowed
   */
  private boolean isAllowed(
      String callerPackage,
      String moduleName,
      List<Entitlement> entitlements,
      Operation op,
      Object arg0,
      int arg1) {
    String capability = op.capabilityName();
    return switch (op.category()) {
      case FILESYSTEM ->
          isAllowedFilesystem(callerPackage, moduleName, entitlements, (Path) arg0, capability);
      case SIMPLE -> isAllowedSimple(callerPackage, moduleName, entitlements, capability);
      case PORT -> isAllowedPort(callerPackage, moduleName, entitlements, arg1, capability);
      case TARGET_PATTERN ->
          isAllowedTargetPattern(
              callerPackage, moduleName, entitlements, (String) arg0, capability);
      case HOST_PORT ->
          isAllowedHostPort(
              callerPackage, moduleName, entitlements, (String) arg0, arg1, capability);
    };
  }

  // ========== CATEGORY HANDLERS ==========

  /**
   * Handles SIMPLE category - no argument matching, just subject check.
   *
   * <p>Used for: network.outbound, threads.create, etc.
   */
  private boolean isAllowedSimple(
      String callerPackage, String moduleName, List<Entitlement> entitlements, String capability) {
    for (Entitlement entitlement : entitlements) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage, moduleName)) {
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
  private boolean isAllowedPort(
      String callerPackage,
      String moduleName,
      List<Entitlement> entitlements,
      int port,
      String capability) {
    for (Entitlement entitlement : entitlements) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage, moduleName)) {
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
      String callerPackage,
      String moduleName,
      List<Entitlement> entitlements,
      String host,
      int port,
      String capability) {
    // Port 0 is not a valid destination for outbound connections
    if (port == 0) {
      LOG.debug("{} denied: port 0 is invalid destination", capability);
      return false;
    }

    for (Entitlement entitlement : entitlements) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage, moduleName)) {
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
  private boolean isAllowedTargetPattern(
      String callerPackage,
      String moduleName,
      List<Entitlement> entitlements,
      String target,
      String capability) {
    boolean isBulkAccess = (target == null);

    for (Entitlement entitlement : entitlements) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage, moduleName)) {
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
  private boolean isAllowedFilesystem(
      String callerPackage,
      String moduleName,
      List<Entitlement> entitlements,
      Path path,
      String capability) {
    Path absPath = path.toAbsolutePath().normalize();

    // Check all entitlements that apply to this caller
    for (Entitlement entitlement : entitlements) {
      if (!entitlement.capability().name().equals(capability)) {
        continue;
      }
      if (!subjectMatches(entitlement.subject(), callerPackage, moduleName)) {
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

  private boolean subjectMatches(SubjectPattern subject, String callerPackage, String moduleName) {
    return switch (subject.type()) {
      case MODULE ->
          // Module-wide grant: matches any package in this module.
          // For unnamed modules (classpath), allow any package since classpath code
          // can come from arbitrary packages.
          ApplicationPolicy.UNNAMED_MODULE.equals(moduleName)
              || callerPackage.startsWith(moduleName);
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
    for (ModulePolicy module : policy.modules()) {
      LOG.debug("Module: {}", module.moduleName());
      for (Entitlement entitlement : module.entitlements()) {
        LOG.debug("  Entitlement: {}", entitlement);
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

  private SecurityException deniedNoPolicy(
      String callerPackage, String callerModule, String details) {
    String message =
        String.format(
            "jGuard: access denied - no policy for module '%s' (package='%s', operation=%s). "
                + "Known modules: %s",
            callerModule, callerPackage, details, getModuleNames());
    return new SecurityException(message);
  }
}
