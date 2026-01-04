/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.bootstrap;

import java.nio.file.Path;

/**
 * Agent configuration parsed from system properties.
 *
 * <p>This class is the single source of truth for all agent configuration. It reads system
 * properties at initialization time and provides immutable access to configuration values.
 *
 * <h2>System Properties</h2>
 *
 * <ul>
 *   <li><b>jguard.policy</b> (required): Path to policy file
 *   <li><b>jguard.mode</b> (default: strict): Enforcement mode (strict/permissive/audit)
 *   <li><b>jguard.log.level</b> (default: info): Log level (error/warn/info/debug/trace)
 *   <li><b>jguard.log.denied</b> (default: true): Log denied operations
 *   <li><b>jguard.log.allowed</b> (default: false): Log allowed operations
 *   <li><b>jguard.reload</b> (default: false): Enable policy hot reload
 *   <li><b>jguard.reload.interval</b> (default: 5): Hot reload poll interval in seconds
 * </ul>
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * AgentConfig config = AgentConfig.fromSystemProperties(agentArgs);
 * if (config.mode().blocksOnDenied()) {
 *     throw new SecurityException("Access denied");
 * }
 * }</pre>
 */
public final class AgentConfig {

  private static final String PROP_POLICY = "jguard.policy";
  private static final String PROP_MODE = "jguard.mode";
  private static final String PROP_LOG_LEVEL = "jguard.log.level";
  private static final String PROP_LOG_DENIED = "jguard.log.denied";
  private static final String PROP_LOG_ALLOWED = "jguard.log.allowed";
  private static final String PROP_RELOAD = "jguard.reload";
  private static final String PROP_RELOAD_INTERVAL = "jguard.reload.interval";

  private final Path policyPath;
  private final EnforcementMode mode;
  private final AgentLogger.Level logLevel;
  private final boolean logDenied;
  private final boolean logAllowed;
  private final boolean hotReloadEnabled;
  private final long hotReloadIntervalSeconds;

  private AgentConfig(Builder builder) {
    this.policyPath = builder.policyPath;
    this.mode = builder.mode;
    this.logLevel = builder.logLevel;
    this.logDenied = builder.logDenied;
    this.logAllowed = builder.logAllowed;
    this.hotReloadEnabled = builder.hotReloadEnabled;
    this.hotReloadIntervalSeconds = builder.hotReloadIntervalSeconds;
  }

  /**
   * Creates an AgentConfig from the agent argument and system properties.
   *
   * @param agentArgs the argument passed to -javaagent (policy path)
   * @return the parsed configuration
   * @throws IllegalArgumentException if required configuration is missing
   */
  public static AgentConfig fromSystemProperties(String agentArgs) {
    Builder builder = new Builder();

    // Policy path: agent arg takes precedence over system property
    String policyStr = agentArgs;
    if (policyStr == null || policyStr.isBlank()) {
      policyStr = System.getProperty(PROP_POLICY);
    }
    if (policyStr == null || policyStr.isBlank()) {
      throw new IllegalArgumentException(
          "No policy file specified. Use: -javaagent:jguard-agent.jar=policy.bin "
              + "or -D"
              + PROP_POLICY
              + "=policy.bin");
    }
    builder.policyPath(Path.of(policyStr));

    // Enforcement mode
    String modeStr = System.getProperty(PROP_MODE);
    if (modeStr != null && !modeStr.isBlank()) {
      builder.mode(EnforcementMode.parse(modeStr));
    }

    // Log level
    String levelStr = System.getProperty(PROP_LOG_LEVEL);
    if (levelStr != null && !levelStr.isBlank()) {
      try {
        builder.logLevel(AgentLogger.Level.valueOf(levelStr.toUpperCase()));
      } catch (IllegalArgumentException e) {
        // Ignore invalid level, use default
      }
    }

    // Log denied
    String logDeniedStr = System.getProperty(PROP_LOG_DENIED);
    if (logDeniedStr != null) {
      builder.logDenied(Boolean.parseBoolean(logDeniedStr));
    }

    // Log allowed
    String logAllowedStr = System.getProperty(PROP_LOG_ALLOWED);
    if (logAllowedStr != null) {
      builder.logAllowed(Boolean.parseBoolean(logAllowedStr));
    }

    // Hot reload
    String reloadStr = System.getProperty(PROP_RELOAD);
    if (reloadStr != null) {
      builder.hotReloadEnabled(Boolean.parseBoolean(reloadStr));
    }

    // Hot reload interval
    String reloadIntervalStr = System.getProperty(PROP_RELOAD_INTERVAL);
    if (reloadIntervalStr != null && !reloadIntervalStr.isBlank()) {
      try {
        builder.hotReloadIntervalSeconds(Long.parseLong(reloadIntervalStr));
      } catch (NumberFormatException e) {
        // Ignore invalid interval, use default
      }
    }

    return builder.build();
  }

  /**
   * Returns the path to the policy file.
   *
   * @return the policy file path
   */
  public Path policyPath() {
    return policyPath;
  }

  /**
   * Returns the enforcement mode.
   *
   * @return the enforcement mode
   */
  public EnforcementMode mode() {
    return mode;
  }

  /**
   * Returns the log level.
   *
   * @return the log level
   */
  public AgentLogger.Level logLevel() {
    return logLevel;
  }

  /**
   * Returns true if denied operations should be logged.
   *
   * @return true if denied operations are logged
   */
  public boolean logDenied() {
    return logDenied;
  }

  /**
   * Returns true if allowed operations should be logged.
   *
   * @return true if allowed operations are logged
   */
  public boolean logAllowed() {
    return logAllowed || mode.logsAllowed();
  }

  /**
   * Returns true if policy hot reload is enabled.
   *
   * @return true if hot reload is enabled
   */
  public boolean hotReloadEnabled() {
    return hotReloadEnabled;
  }

  /**
   * Returns the hot reload poll interval in seconds.
   *
   * @return the poll interval in seconds
   */
  public long hotReloadIntervalSeconds() {
    return hotReloadIntervalSeconds;
  }

  @Override
  public String toString() {
    return "AgentConfig{"
        + "policyPath="
        + policyPath
        + ", mode="
        + mode
        + ", logLevel="
        + logLevel
        + ", logDenied="
        + logDenied
        + ", logAllowed="
        + logAllowed
        + ", hotReloadEnabled="
        + hotReloadEnabled
        + ", hotReloadIntervalSeconds="
        + hotReloadIntervalSeconds
        + '}';
  }

  /** Builder for AgentConfig. */
  public static final class Builder {
    private Path policyPath;
    private EnforcementMode mode = EnforcementMode.STRICT;
    private AgentLogger.Level logLevel = AgentLogger.Level.INFO;
    private boolean logDenied = true;
    private boolean logAllowed = false;
    private boolean hotReloadEnabled = false;
    private long hotReloadIntervalSeconds = 5;

    /** Creates a new Builder with default values. */
    public Builder() {}

    /**
     * Sets the policy file path.
     *
     * @param path the policy file path
     * @return this builder
     */
    public Builder policyPath(Path path) {
      this.policyPath = path;
      return this;
    }

    /**
     * Sets the enforcement mode.
     *
     * @param mode the enforcement mode
     * @return this builder
     */
    public Builder mode(EnforcementMode mode) {
      this.mode = mode;
      return this;
    }

    /**
     * Sets the log level.
     *
     * @param level the log level
     * @return this builder
     */
    public Builder logLevel(AgentLogger.Level level) {
      this.logLevel = level;
      return this;
    }

    /**
     * Sets whether to log denied operations.
     *
     * @param value true to log denied operations
     * @return this builder
     */
    public Builder logDenied(boolean value) {
      this.logDenied = value;
      return this;
    }

    /**
     * Sets whether to log allowed operations.
     *
     * @param value true to log allowed operations
     * @return this builder
     */
    public Builder logAllowed(boolean value) {
      this.logAllowed = value;
      return this;
    }

    /**
     * Sets whether hot reload is enabled.
     *
     * @param value true to enable hot reload
     * @return this builder
     */
    public Builder hotReloadEnabled(boolean value) {
      this.hotReloadEnabled = value;
      return this;
    }

    /**
     * Sets the hot reload poll interval.
     *
     * @param seconds the poll interval in seconds
     * @return this builder
     */
    public Builder hotReloadIntervalSeconds(long seconds) {
      this.hotReloadIntervalSeconds = seconds;
      return this;
    }

    /**
     * Builds the AgentConfig.
     *
     * @return the built configuration
     * @throws IllegalStateException if policyPath is not set
     */
    public AgentConfig build() {
      if (policyPath == null) {
        throw new IllegalStateException("policyPath is required");
      }
      return new AgentConfig(this);
    }
  }
}
