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
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Watches for policy file changes and reloads the PolicyEnforcer when detected.
 *
 * <p>This enables administrators to update entitlements without restarting the JVM. The reloader
 * polls policy files at a configurable interval and atomically swaps the PolicyEnforcer when
 * changes are detected.
 *
 * <p>Supports two modes:
 *
 * <ul>
 *   <li><b>Explicit policy path mode:</b> Watches a policy file and optional override directory.
 *       When either changes, reloads both.
 *   <li><b>Discovery mode:</b> Uses a cached base policy (discovered from JARs at startup) and
 *       watches only the override directory. When overrides change, re-merges with the cached base.
 * </ul>
 *
 * <p>When an override directory is configured via {@code jguard.policy.override}, the reloader
 * watches for changes to override files and applies restrictive merging using {@link PolicyMerger}.
 *
 * <p>Usage (explicit path mode):
 *
 * <pre>{@code
 * PolicyReloader reloader = new PolicyReloader(policyPath, enforcerRef, config);
 * reloader.start();
 * }</pre>
 *
 * <p>Usage (discovery mode with override hot reload):
 *
 * <pre>{@code
 * ApplicationPolicy basePolicy = PolicyDiscovery.discoverEmbedded(config);
 * PolicyReloader reloader = PolicyReloader.forDiscoveryMode(basePolicy, enforcerRef, config);
 * reloader.start();
 * }</pre>
 *
 * <p>The reloader uses a daemon thread and will not prevent JVM shutdown.
 */
public final class PolicyReloader {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyReloader.class);

  /** Default polling interval in seconds. */
  private static final long DEFAULT_POLL_INTERVAL_SECONDS = 5;

  // For explicit policy path mode
  private final Path policyPath;

  // For discovery mode - cached base policy from JARs
  private final ApplicationPolicy basePolicy;

  private final AtomicReference<PolicyEnforcer> enforcerRef;
  private final AgentConfig config;
  private final long pollIntervalSeconds;
  private final ScheduledExecutorService scheduler;

  private volatile FileTime lastModifiedTime;
  private volatile FileTime lastOverrideDirModifiedTime;
  private volatile boolean running;

  /**
   * Creates a new policy reloader for explicit policy path mode.
   *
   * @param policyPath the path to the policy file to watch
   * @param enforcerRef atomic reference to the current PolicyEnforcer
   * @param config the agent configuration
   */
  public PolicyReloader(
      Path policyPath, AtomicReference<PolicyEnforcer> enforcerRef, AgentConfig config) {
    this(policyPath, enforcerRef, config, DEFAULT_POLL_INTERVAL_SECONDS);
  }

  /**
   * Creates a new policy reloader for explicit policy path mode with custom poll interval.
   *
   * @param policyPath the path to the policy file to watch
   * @param enforcerRef atomic reference to the current PolicyEnforcer
   * @param config the agent configuration
   * @param pollIntervalSeconds interval between file checks in seconds
   */
  public PolicyReloader(
      Path policyPath,
      AtomicReference<PolicyEnforcer> enforcerRef,
      AgentConfig config,
      long pollIntervalSeconds) {
    this.policyPath = policyPath;
    this.basePolicy = null; // Not in discovery mode
    this.enforcerRef = enforcerRef;
    this.config = config;
    this.pollIntervalSeconds = pollIntervalSeconds;
    this.scheduler = createScheduler();

    // Initialize last modified time for policy file
    try {
      this.lastModifiedTime = Files.getLastModifiedTime(policyPath);
    } catch (IOException e) {
      LOG.warn("Could not read initial policy file timestamp: {}", e.getMessage());
      this.lastModifiedTime = null;
    }

    initializeOverrideDirTimestamp();
  }

  /**
   * Creates a new policy reloader for discovery mode (override-only hot reload).
   *
   * <p>In this mode, the base policy (discovered from JARs) is cached and only the override
   * directory is watched. When overrides change, they are re-merged with the cached base policy.
   *
   * @param basePolicy the base policy discovered from JARs (immutable)
   * @param enforcerRef atomic reference to the current PolicyEnforcer
   * @param config the agent configuration (must have overrideDir set)
   * @param pollIntervalSeconds interval between file checks in seconds
   * @return a new PolicyReloader configured for discovery mode
   * @throws IllegalArgumentException if no override directory is configured
   */
  public static PolicyReloader forDiscoveryMode(
      ApplicationPolicy basePolicy,
      AtomicReference<PolicyEnforcer> enforcerRef,
      AgentConfig config,
      long pollIntervalSeconds) {
    if (config.overrideDirs().isEmpty()) {
      throw new IllegalArgumentException(
          "Hot reload in discovery mode requires an override directory "
              + "(set -Djguard.policy.override=<dir>)");
    }
    return new PolicyReloader(basePolicy, enforcerRef, config, pollIntervalSeconds);
  }

  /**
   * Private constructor for discovery mode.
   *
   * @param basePolicy the base policy discovered from JARs
   * @param enforcerRef atomic reference to the current PolicyEnforcer
   * @param config the agent configuration
   * @param pollIntervalSeconds interval between file checks in seconds
   */
  private PolicyReloader(
      ApplicationPolicy basePolicy,
      AtomicReference<PolicyEnforcer> enforcerRef,
      AgentConfig config,
      long pollIntervalSeconds) {
    this.policyPath = null; // Not watching a policy file
    this.basePolicy = basePolicy;
    this.enforcerRef = enforcerRef;
    this.config = config;
    this.pollIntervalSeconds = pollIntervalSeconds;
    this.scheduler = createScheduler();

    // No policy file to watch in discovery mode
    this.lastModifiedTime = null;

    initializeOverrideDirTimestamp();
  }

  private ScheduledExecutorService createScheduler() {
    return Executors.newSingleThreadScheduledExecutor(
        r -> {
          Thread t = new Thread(r, "jguard-policy-reloader");
          t.setDaemon(true);
          return t;
        });
  }

  private void initializeOverrideDirTimestamp() {
    List<Path> overrideDirs = config.overrideDirs();
    if (!overrideDirs.isEmpty()) {
      try {
        this.lastOverrideDirModifiedTime = getOverrideDirsModifiedTime(overrideDirs);
      } catch (IOException e) {
        LOG.warn("Could not read initial override directory timestamp: {}", e.getMessage());
        this.lastOverrideDirModifiedTime = null;
      }
    }
  }

  /** Returns true if this reloader is in discovery mode (override-only). */
  public boolean isDiscoveryMode() {
    return basePolicy != null;
  }

  /**
   * Starts the policy reloader.
   *
   * <p>The reloader will poll policy files at the configured interval and reload the PolicyEnforcer
   * when changes are detected.
   */
  public void start() {
    if (running) {
      LOG.warn("Policy reloader already running");
      return;
    }

    running = true;
    scheduler.scheduleAtFixedRate(
        this::checkAndReload, pollIntervalSeconds, pollIntervalSeconds, TimeUnit.SECONDS);

    List<Path> overrideDirs = config.overrideDirs();
    if (isDiscoveryMode()) {
      LOG.info(
          "Policy hot reload enabled (discovery mode): watching override directories {} (interval={}s)",
          overrideDirs,
          pollIntervalSeconds);
    } else if (!overrideDirs.isEmpty()) {
      LOG.info(
          "Policy hot reload enabled: watching {} and override directories {} (interval={}s)",
          policyPath,
          overrideDirs,
          pollIntervalSeconds);
    } else {
      LOG.info(
          "Policy hot reload enabled: watching {} (interval={}s)", policyPath, pollIntervalSeconds);
    }
  }

  /** Stops the policy reloader. */
  public void stop() {
    running = false;
    scheduler.shutdown();
    try {
      if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
        scheduler.shutdownNow();
      }
    } catch (InterruptedException e) {
      scheduler.shutdownNow();
      Thread.currentThread().interrupt();
    }
    LOG.info("Policy reloader stopped");
  }

  /** Checks if policy files have changed and reloads if necessary. */
  private void checkAndReload() {
    try {
      boolean policyChanged = false;
      boolean overridesChanged = false;

      // In discovery mode, we don't watch a policy file
      if (!isDiscoveryMode()) {
        if (!Files.exists(policyPath)) {
          LOG.warn("Policy file no longer exists: {}", policyPath);
          return;
        }

        // Check if policy file has been modified
        FileTime currentModifiedTime = Files.getLastModifiedTime(policyPath);
        if (lastModifiedTime == null || currentModifiedTime.compareTo(lastModifiedTime) > 0) {
          policyChanged = true;
          lastModifiedTime = currentModifiedTime;
        }
      }

      // Check if any override directory has changed
      List<Path> overrideDirs = config.overrideDirs();
      if (!overrideDirs.isEmpty()) {
        FileTime currentOverrideModifiedTime = getOverrideDirsModifiedTime(overrideDirs);
        if (lastOverrideDirModifiedTime == null
            || currentOverrideModifiedTime.compareTo(lastOverrideDirModifiedTime) > 0) {
          overridesChanged = true;
          lastOverrideDirModifiedTime = currentOverrideModifiedTime;
        }
      }

      // Reload if anything changed
      if (policyChanged || overridesChanged) {
        if (isDiscoveryMode()) {
          LOG.info("Override files changed, reloading from: {}", overrideDirs);
        } else if (policyChanged && overridesChanged) {
          LOG.info("Policy and override files changed, reloading");
        } else if (policyChanged) {
          LOG.info("Policy file changed, reloading: {}", policyPath);
        } else {
          LOG.info("Override files changed, reloading from: {}", overrideDirs);
        }
        reload();
      }
    } catch (Exception e) {
      LOG.error("Error checking policy file for changes: {}", e.getMessage());
    }
  }

  /** Reloads the policy and swaps the PolicyEnforcer. */
  private void reload() {
    try {
      ApplicationPolicy policy;

      if (isDiscoveryMode()) {
        // In discovery mode, use the cached base policy
        policy = basePolicy;
      } else {
        // In explicit path mode, reload from file (supports v1 and v2)
        try (InputStream is = Files.newInputStream(policyPath)) {
          policy = BinaryPolicyReader.readApplicationPolicy(is);
        }
      }

      // Apply overrides if configured (later directories take precedence)
      for (Path overrideDir : config.overrideDirs()) {
        if (Files.isDirectory(overrideDir)) {
          policy = PolicyMerger.merge(policy, overrideDir);
        }
      }

      // Create new enforcer
      PolicyEnforcer newEnforcer = new PolicyEnforcer(policy, config);

      // Validate policy before applying
      PolicyEnforcer oldEnforcer = enforcerRef.get();
      PolicyValidationResult validation = validatePolicyChange(oldEnforcer, newEnforcer);

      if (validation.hasBlockingIssues()) {
        LOG.error("Policy reload BLOCKED due to validation errors:");
        for (String error : validation.errors()) {
          LOG.error("  - {}", error);
        }
        LOG.error("Fix the policy and try again. Current policy remains in effect.");
        return;
      }

      if (validation.hasWarnings()) {
        LOG.warn("Policy validation warnings ({} issue(s)):", validation.warnings().size());
        for (String warning : validation.warnings()) {
          LOG.warn("  - {}", warning);
        }
      }

      // Atomic swap
      enforcerRef.set(newEnforcer);

      LOG.info(
          "Policy reloaded successfully: {} module(s), modules={}",
          policy.modules().size(),
          newEnforcer.getModuleNames());

      // Log if modules changed (unusual in discovery mode, possible in explicit path mode)
      if (oldEnforcer != null) {
        java.util.Set<String> oldModules = new java.util.HashSet<>(oldEnforcer.getModuleNames());
        java.util.Set<String> newModules = new java.util.HashSet<>(newEnforcer.getModuleNames());
        if (!oldModules.equals(newModules)) {
          LOG.warn("Policy modules changed: {} -> {}", oldModules, newModules);
        }
      }
    } catch (IOException e) {
      LOG.error("Failed to reload policy: {}", e.getMessage());
    } catch (Exception e) {
      LOG.error("Unexpected error reloading policy: {}", e.getMessage());
    }
  }

  /**
   * Result of policy validation.
   *
   * @param errors blocking errors that prevent the reload
   * @param warnings non-blocking warnings
   */
  private record PolicyValidationResult(List<String> errors, List<String> warnings) {
    boolean hasBlockingIssues() {
      return !errors.isEmpty();
    }

    boolean hasWarnings() {
      return !warnings.isEmpty();
    }
  }

  /**
   * Validates a policy change and returns validation results.
   *
   * <p>This checks for capability removals that could cause runtime issues. If a capability that
   * was previously granted is now removed, operations that depend on that capability will start
   * failing with SecurityExceptions.
   *
   * <p>Validation is informational - it warns about potential issues but does not block the reload
   * (unless critical errors are detected).
   *
   * @param oldEnforcer the current enforcer (may be null on first load)
   * @param newEnforcer the new enforcer to validate
   * @return validation result with errors and warnings
   */
  private PolicyValidationResult validatePolicyChange(
      PolicyEnforcer oldEnforcer, PolicyEnforcer newEnforcer) {
    List<String> errors = new java.util.ArrayList<>();
    List<String> warnings = new java.util.ArrayList<>();

    if (oldEnforcer == null) {
      // First load - no comparison needed
      return new PolicyValidationResult(errors, warnings);
    }

    // Compare old and new policies to detect capability removals
    var oldPolicy = oldEnforcer.getPolicy();
    var newPolicy = newEnforcer.getPolicy();

    for (var oldModule : oldPolicy.modules()) {
      String moduleName = oldModule.moduleName();
      var newModuleOpt =
          newPolicy.modules().stream().filter(m -> m.moduleName().equals(moduleName)).findFirst();

      if (newModuleOpt.isEmpty()) {
        // Module was removed entirely
        warnings.add("Module '" + moduleName + "' was removed from policy");
        continue;
      }

      var newModule = newModuleOpt.get();

      // Check for removed capabilities
      java.util.Set<String> oldCaps =
          oldModule.entitlements().stream()
              .map(e -> formatCapability(e))
              .collect(java.util.stream.Collectors.toSet());
      java.util.Set<String> newCaps =
          newModule.entitlements().stream()
              .map(e -> formatCapability(e))
              .collect(java.util.stream.Collectors.toSet());

      // Find removed capabilities
      java.util.Set<String> removed = new java.util.HashSet<>(oldCaps);
      removed.removeAll(newCaps);

      if (!removed.isEmpty()) {
        warnings.add(
            "Module '"
                + moduleName
                + "': "
                + removed.size()
                + " capability(s) removed: "
                + removed);
      }

      // Find added capabilities (informational)
      java.util.Set<String> added = new java.util.HashSet<>(newCaps);
      added.removeAll(oldCaps);

      if (!added.isEmpty()) {
        LOG.debug("Module '{}': {} capability(s) added: {}", moduleName, added.size(), added);
      }
    }

    return new PolicyValidationResult(errors, warnings);
  }

  /** Formats an entitlement as a capability string for comparison. */
  private String formatCapability(io.jguard.policy.model.Entitlement e) {
    String base = e.capability().name();
    var args = e.capability().arguments();
    if (args.isEmpty()) {
      return base;
    }
    StringBuilder sb = new StringBuilder(base).append("(");
    for (int i = 0; i < args.size(); i++) {
      if (i > 0) sb.append(", ");
      sb.append(args.get(i));
    }
    return sb.append(")").toString();
  }

  /** Returns true if the reloader is currently running. */
  public boolean isRunning() {
    return running;
  }

  /**
   * Gets the latest modification time across all override directories.
   *
   * @param overrideDirs the override directories
   * @return the latest modification time across all directories
   * @throws IOException if reading any directory fails
   */
  private FileTime getOverrideDirsModifiedTime(List<Path> overrideDirs) throws IOException {
    FileTime latest = null;
    for (Path overrideDir : overrideDirs) {
      if (Files.isDirectory(overrideDir)) {
        FileTime dirTime = getOverrideDirModifiedTime(overrideDir);
        if (latest == null || dirTime.compareTo(latest) > 0) {
          latest = dirTime;
        }
      }
    }
    // If no directories exist yet, use epoch
    return latest != null ? latest : FileTime.fromMillis(0);
  }

  /**
   * Gets the latest modification time of any .bin file in a single override directory.
   *
   * @param overrideDir the override directory
   * @return the latest modification time
   * @throws IOException if reading directory fails
   */
  private FileTime getOverrideDirModifiedTime(Path overrideDir) throws IOException {
    FileTime latest = Files.getLastModifiedTime(overrideDir);

    try (DirectoryStream<Path> stream = Files.newDirectoryStream(overrideDir, "*.bin")) {
      for (Path file : stream) {
        FileTime fileTime = Files.getLastModifiedTime(file);
        if (fileTime.compareTo(latest) > 0) {
          latest = fileTime;
        }
      }
    }

    return latest;
  }
}
