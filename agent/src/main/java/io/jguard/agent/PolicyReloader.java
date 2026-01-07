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
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Watches for policy file changes and reloads the PolicyEnforcer when detected.
 *
 * <p>This enables administrators to update entitlements without restarting the JVM. The reloader
 * polls the policy file at a configurable interval and atomically swaps the PolicyEnforcer when
 * changes are detected.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * AtomicReference<PolicyEnforcer> enforcerRef = new AtomicReference<>(enforcer);
 * PolicyReloader reloader = new PolicyReloader(policyPath, enforcerRef, config);
 * reloader.start();
 * }</pre>
 *
 * <p>The reloader uses a daemon thread and will not prevent JVM shutdown.
 */
public final class PolicyReloader {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyReloader.class);

  /** Default polling interval in seconds. */
  private static final long DEFAULT_POLL_INTERVAL_SECONDS = 5;

  private final Path policyPath;
  private final AtomicReference<PolicyEnforcer> enforcerRef;
  private final AgentConfig config;
  private final long pollIntervalSeconds;
  private final ScheduledExecutorService scheduler;

  private volatile FileTime lastModifiedTime;
  private volatile boolean running;

  /**
   * Creates a new policy reloader.
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
   * Creates a new policy reloader with custom poll interval.
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
    this.enforcerRef = enforcerRef;
    this.config = config;
    this.pollIntervalSeconds = pollIntervalSeconds;
    this.scheduler =
        Executors.newSingleThreadScheduledExecutor(
            r -> {
              Thread t = new Thread(r, "jguard-policy-reloader");
              t.setDaemon(true);
              return t;
            });

    // Initialize last modified time
    try {
      this.lastModifiedTime = Files.getLastModifiedTime(policyPath);
    } catch (IOException e) {
      LOG.warn("Could not read initial policy file timestamp: {}", e.getMessage());
      this.lastModifiedTime = null;
    }
  }

  /**
   * Starts the policy reloader.
   *
   * <p>The reloader will poll the policy file at the configured interval and reload the
   * PolicyEnforcer when changes are detected.
   */
  public void start() {
    if (running) {
      LOG.warn("Policy reloader already running");
      return;
    }

    running = true;
    scheduler.scheduleAtFixedRate(
        this::checkAndReload, pollIntervalSeconds, pollIntervalSeconds, TimeUnit.SECONDS);

    LOG.info(
        "Policy hot reload enabled: watching {} (interval={}s)", policyPath, pollIntervalSeconds);
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

  /** Checks if the policy file has changed and reloads if necessary. */
  private void checkAndReload() {
    try {
      if (!Files.exists(policyPath)) {
        LOG.warn("Policy file no longer exists: {}", policyPath);
        return;
      }

      FileTime currentModifiedTime = Files.getLastModifiedTime(policyPath);

      // Check if file has been modified
      if (lastModifiedTime == null || currentModifiedTime.compareTo(lastModifiedTime) > 0) {
        LOG.info("Policy file changed, reloading: {}", policyPath);
        reload();
        lastModifiedTime = currentModifiedTime;
      }
    } catch (Exception e) {
      LOG.error("Error checking policy file for changes: {}", e.getMessage());
    }
  }

  /** Reloads the policy from disk and swaps the PolicyEnforcer. */
  private void reload() {
    try {
      // Read new policy
      PolicyDescriptor newPolicy = BinaryPolicyReader.fromFile(policyPath);

      // Create new enforcer
      PolicyEnforcer newEnforcer = new PolicyEnforcer(newPolicy, config);

      // Atomic swap
      PolicyEnforcer oldEnforcer = enforcerRef.getAndSet(newEnforcer);

      LOG.info(
          "Policy reloaded successfully: module={}, entitlements={}",
          newPolicy.moduleName(),
          newPolicy.entitlements().size());

      // Log if module name changed (unusual but possible)
      if (oldEnforcer != null) {
        String oldModule = oldEnforcer.getModuleName();
        String newModule = newPolicy.moduleName();
        if (!oldModule.equals(newModule)) {
          LOG.warn("Policy module name changed: {} -> {}", oldModule, newModule);
        }
      }
    } catch (IOException e) {
      LOG.error("Failed to reload policy: {}", e.getMessage());
    } catch (Exception e) {
      LOG.error("Unexpected error reloading policy: {}", e.getMessage());
    }
  }

  /** Returns true if the reloader is currently running. */
  public boolean isRunning() {
    return running;
  }
}
