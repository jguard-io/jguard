/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.bootstrap;

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
 *   <li><b>jguard.policy</b>: Path to policy file (required unless discovery is enabled)
 *   <li><b>jguard.mode</b> (default: strict): Enforcement mode (strict/permissive/audit)
 *   <li><b>jguard.log.level</b> (default: info): Log level (error/warn/info/debug/trace)
 *   <li><b>jguard.log.denied</b> (default: true): Log denied operations
 *   <li><b>jguard.log.allowed</b> (default: false): Log allowed operations
 *   <li><b>jguard.reload</b> (default: false): Enable policy hot reload
 *   <li><b>jguard.reload.interval</b> (default: 5): Hot reload poll interval in seconds
 *   <li><b>jguard.discovery</b> (default: true): Enable embedded policy discovery from JARs
 *   <li><b>jguard.allowUnsignedPolicies</b> (default: false): Allow policies from unsigned JARs
 *   <li><b>jguard.policy.unnamed</b>: Path to policy for unnamed module (classpath code)
 *   <li><b>jguard.policy.override</b>: Path to override directory (can only restrict, not expand)
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
  private static final String PROP_DISCOVERY = "jguard.discovery";
  private static final String PROP_ALLOW_UNSIGNED = "jguard.allowUnsignedPolicies";
  private static final String PROP_UNNAMED_POLICY = "jguard.policy.unnamed";
  private static final String PROP_OVERRIDE_DIR = "jguard.policy.override";

  private final Path policyPath;
  private final EnforcementMode mode;
  private final AgentLogger.Level logLevel;
  private final boolean logDenied;
  private final boolean logAllowed;
  private final boolean hotReloadEnabled;
  private final long hotReloadIntervalSeconds;
  private final boolean discoveryEnabled;
  private final boolean allowUnsignedPolicies;
  private final Path unnamedModulePolicy;
  private final Path overrideDir;

  private AgentConfig(Builder builder) {
    this.policyPath = builder.policyPath;
    this.mode = builder.mode;
    this.logLevel = builder.logLevel;
    this.logDenied = builder.logDenied;
    this.logAllowed = builder.logAllowed;
    this.hotReloadEnabled = builder.hotReloadEnabled;
    this.hotReloadIntervalSeconds = builder.hotReloadIntervalSeconds;
    this.discoveryEnabled = builder.discoveryEnabled;
    this.allowUnsignedPolicies = builder.allowUnsignedPolicies;
    this.unnamedModulePolicy = builder.unnamedModulePolicy;
    this.overrideDir = builder.overrideDir;
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

    // Discovery mode: defaults to true (auto-discover from signed JARs)
    String discoveryStr = System.getProperty(PROP_DISCOVERY);
    boolean discovery = discoveryStr == null || Boolean.parseBoolean(discoveryStr);

    // Policy path: agent arg takes precedence over system property
    String policyStr = agentArgs;
    if (policyStr == null || policyStr.isBlank()) {
      policyStr = System.getProperty(PROP_POLICY);
    }

    // Policy path is required only if discovery is disabled
    if (policyStr == null || policyStr.isBlank()) {
      if (!discovery) {
        throw new IllegalArgumentException(
            "No policy file specified and discovery is disabled. Use: "
                + "-javaagent:jguard-agent.jar=policy.bin or -D"
                + PROP_POLICY
                + "=policy.bin");
      }
      // Discovery mode - no explicit policy path needed
      builder.discoveryEnabled(true);
    } else {
      // Explicit policy path provided - use it, disable discovery
      builder.policyPath(Path.of(policyStr));
      builder.discoveryEnabled(false);
    }

    // Allow unsigned policies (development mode)
    String allowUnsignedStr = System.getProperty(PROP_ALLOW_UNSIGNED);
    if (allowUnsignedStr != null) {
      builder.allowUnsignedPolicies(Boolean.parseBoolean(allowUnsignedStr));
    }

    // Unnamed module policy path
    String unnamedPolicyStr = System.getProperty(PROP_UNNAMED_POLICY);
    if (unnamedPolicyStr != null && !unnamedPolicyStr.isBlank()) {
      builder.unnamedModulePolicy(Path.of(unnamedPolicyStr));
    }

    // Policy override directory
    String overrideDirStr = System.getProperty(PROP_OVERRIDE_DIR);
    if (overrideDirStr != null && !overrideDirStr.isBlank()) {
      builder.overrideDir(Path.of(overrideDirStr));
    }

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

  /**
   * Returns true if embedded policy discovery from JARs is enabled.
   *
   * <p>When enabled, the agent scans the module path for signed JARs containing embedded policies
   * at {@code META-INF/jguard/policy.bin}.
   *
   * @return true if discovery is enabled
   */
  public boolean discoveryEnabled() {
    return discoveryEnabled;
  }

  /**
   * Returns true if policies from unsigned JARs are allowed.
   *
   * <p>This should only be enabled for development/testing. In production, policies should only be
   * loaded from signed JARs to prevent malicious code from granting itself capabilities.
   *
   * @return true if unsigned policies are allowed
   */
  public boolean allowUnsignedPolicies() {
    return allowUnsignedPolicies;
  }

  /**
   * Returns the path to the policy file for the unnamed module (classpath code).
   *
   * <p>When running with discovery enabled, classpath code (unnamed module) needs an explicit
   * policy since it doesn't come from a signed JAR.
   *
   * @return the unnamed module policy path, or null if not specified
   */
  public Path unnamedModulePolicy() {
    return unnamedModulePolicy;
  }

  /**
   * Returns the path to the policy override directory.
   *
   * <p>When set, the agent loads override files from this directory and merges them with embedded
   * policies. Override semantics are restrictive-only: overrides can only REMOVE capabilities from
   * the embedded policy, never add.
   *
   * <p>Expected directory structure:
   *
   * <pre>
   * /etc/myapp/overrides/
   * ├── com.example.core.bin       # Override for com.example.core module
   * ├── com.example.transport.bin  # Override for com.example.transport module
   * └── _global.bin                # Global override (applies to ALL modules)
   * </pre>
   *
   * @return the override directory path, or null if not specified
   */
  public Path overrideDir() {
    return overrideDir;
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
        + ", discoveryEnabled="
        + discoveryEnabled
        + ", allowUnsignedPolicies="
        + allowUnsignedPolicies
        + ", unnamedModulePolicy="
        + unnamedModulePolicy
        + ", overrideDir="
        + overrideDir
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
    private boolean discoveryEnabled = false;
    private boolean allowUnsignedPolicies = false;
    private Path unnamedModulePolicy;
    private Path overrideDir;

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
     * Sets whether embedded policy discovery is enabled.
     *
     * @param value true to enable discovery from signed JARs
     * @return this builder
     */
    public Builder discoveryEnabled(boolean value) {
      this.discoveryEnabled = value;
      return this;
    }

    /**
     * Sets whether policies from unsigned JARs are allowed.
     *
     * @param value true to allow unsigned policies (development only)
     * @return this builder
     */
    public Builder allowUnsignedPolicies(boolean value) {
      this.allowUnsignedPolicies = value;
      return this;
    }

    /**
     * Sets the policy path for the unnamed module (classpath code).
     *
     * @param path the policy file path for unnamed module
     * @return this builder
     */
    public Builder unnamedModulePolicy(Path path) {
      this.unnamedModulePolicy = path;
      return this;
    }

    /**
     * Sets the policy override directory.
     *
     * <p>Files in this directory can restrict (but not expand) embedded policies. See {@link
     * AgentConfig#overrideDir()} for expected directory structure.
     *
     * @param path the override directory path
     * @return this builder
     */
    public Builder overrideDir(Path path) {
      this.overrideDir = path;
      return this;
    }

    /**
     * Builds the AgentConfig.
     *
     * @return the built configuration
     * @throws IllegalStateException if policyPath is not set and discovery is disabled
     */
    public AgentConfig build() {
      if (policyPath == null && !discoveryEnabled) {
        throw new IllegalStateException("policyPath is required when discovery is disabled");
      }
      return new AgentConfig(this);
    }
  }
}
