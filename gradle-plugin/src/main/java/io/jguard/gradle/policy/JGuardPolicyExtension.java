/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.gradle.policy;

import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;

/**
 * Configuration extension for the jGuard policy plugin.
 *
 * <p>Example usage in build.gradle:
 *
 * <pre>
 * jguardPolicy {
 *     sourceFile = file("src/main/jguard/module-info.jguard")
 *     outputDir = layout.buildDirectory.dir("generated/jguard")
 *     includeJson = true
 *     mode = "strict"  // strict, permissive, or audit
 * }
 * </pre>
 *
 * <p>Run with agent: {@code ./gradlew runWithAgent}
 *
 * <p>Properties:
 *
 * <ul>
 *   <li>{@code -Pjguard.skip=true} - Skip agent enforcement
 *   <li>{@code -Pjguard.mode=audit} - Override enforcement mode
 * </ul>
 */
public abstract class JGuardPolicyExtension {

  /**
   * The source policy descriptor file.
   *
   * <p>Default: {@code src/main/jguard/module-info.jguard}
   */
  public abstract RegularFileProperty getSourceFile();

  /**
   * The output directory for compiled policy files.
   *
   * <p>Default: {@code build/generated/jguard/}
   */
  public abstract DirectoryProperty getOutputDir();

  /**
   * Whether to generate a JSON representation alongside the binary.
   *
   * <p>Default: {@code true}
   */
  public abstract Property<Boolean> getIncludeJson();

  /**
   * The name of the binary policy file.
   *
   * <p>Default: {@code policy.bin}
   */
  public abstract Property<String> getBinName();

  /**
   * The name of the JSON policy file.
   *
   * <p>Default: {@code policy.json}
   */
  public abstract Property<String> getJsonName();

  /**
   * The path within the JAR where policy files are placed.
   *
   * <p>Default: {@code META-INF/jguard}
   */
  public abstract Property<String> getJarPath();

  /**
   * The enforcement mode for the agent.
   *
   * <p>Valid values: {@code strict}, {@code permissive}, {@code audit}
   *
   * <p>Default: {@code strict}
   */
  public abstract Property<String> getMode();

  /**
   * The log level for the agent.
   *
   * <p>Valid values: {@code error}, {@code warn}, {@code info}, {@code debug}, {@code trace}
   *
   * <p>Default: {@code info}
   */
  public abstract Property<String> getLogLevel();

  /**
   * Whether to use policy discovery mode (automatic policy detection from JARs).
   *
   * <p>When enabled (the default), the agent discovers policies from all module JARs on the
   * classpath instead of loading a single policy file. This works for both single-module and
   * multi-module JPMS applications.
   *
   * <p>Set to {@code false} to use explicit single-module mode where the compiled policy file is
   * passed directly to the agent.
   *
   * <p>Default: {@code true}
   */
  public abstract Property<Boolean> getDiscoveryMode();

  /**
   * Whether to allow policies from unsigned JARs during discovery.
   *
   * <p>For development, set this to {@code true} since JARs are typically not signed during
   * development. For production, leave as {@code false} to only load policies from signed JARs.
   *
   * <p>Default: {@code false}
   */
  public abstract Property<Boolean> getAllowUnsignedPolicies();

  // ========================================================================
  // External Policies Configuration
  // ========================================================================

  /**
   * The source directory containing external policy {@code .jguard} files.
   *
   * <p>All {@code *.jguard} files in this directory will be compiled to binary format. The output
   * filename will be derived from the source filename (e.g., {@code _global.jguard} becomes {@code
   * _global.bin}, {@code com.example.lib.jguard} becomes {@code com.example.lib.bin}).
   *
   * <p>Default: not set (external policy compilation disabled)
   *
   * <p>Example usage:
   *
   * <pre>
   * jguardPolicy {
   *     externalPoliciesSourceDir = file("policies-src")
   *     externalPoliciesOutputDir = file("policies")
   * }
   * </pre>
   */
  public abstract DirectoryProperty getExternalPoliciesSourceDir();

  /**
   * The output directory for compiled external policy {@code .bin} files.
   *
   * <p>This is the directory that should be passed to the jGuard agent via {@code
   * -Djguard.policy.override=/path/to/policies}.
   *
   * <p>Default: {@code build/external-policies/}
   */
  public abstract DirectoryProperty getExternalPoliciesOutputDir();

  /**
   * Whether to generate JSON alongside binary for external policies (for debugging).
   *
   * <p>Default: {@code false}
   */
  public abstract Property<Boolean> getExternalPoliciesIncludeJson();

  // ========================================================================
  // Hot Reload Configuration
  // ========================================================================

  /**
   * Whether to enable policy hot reload.
   *
   * <p>When enabled, the agent watches for policy file changes and reloads them without requiring a
   * JVM restart. This is useful for:
   *
   * <ul>
   *   <li>Development: quickly iterate on policy definitions
   *   <li>Operations: adjust permissions without service restarts
   *   <li>Emergency response: rapidly restrict compromised modules
   * </ul>
   *
   * <p>In discovery mode, hot reload watches the external policy override directory. In explicit
   * policy mode, it watches both the policy file and override directory.
   *
   * <p>Default: {@code false}
   */
  public abstract Property<Boolean> getHotReload();

  /**
   * The interval in seconds between policy file checks when hot reload is enabled.
   *
   * <p>Lower values provide faster response to changes but increase overhead. Higher values reduce
   * overhead but delay detection of changes.
   *
   * <p>Default: {@code 5} seconds
   */
  public abstract Property<Integer> getHotReloadInterval();
}
