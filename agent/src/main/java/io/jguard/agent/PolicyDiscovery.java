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
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Discovers embedded jGuard policies from JARs on the module/class path.
 *
 * <p>This class scans JARs for embedded policies at {@code META-INF/jguard/policy.bin} and builds
 * an {@link ApplicationPolicy} containing all discovered module policies.
 *
 * <h2>Security Model</h2>
 *
 * <p>By default, policies are only loaded from signed JARs. This prevents malicious unsigned code
 * from granting itself capabilities. The {@code jguard.allowUnsignedPolicies} system property can
 * be set to {@code true} for development/testing.
 *
 * <h2>Duplicate Detection</h2>
 *
 * <p>If two JARs contain policies for the same module name, discovery fails with a clear error.
 * This prevents confusion about which policy applies.
 */
public final class PolicyDiscovery {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyDiscovery.class);

  private PolicyDiscovery() {
    // Static utility class
  }

  /**
   * Discovers all embedded policies from the module/class path.
   *
   * @param config the agent configuration
   * @return the combined application policy
   * @throws PolicyDiscoveryException if discovery fails (duplicate modules, invalid policies, etc.)
   */
  public static ApplicationPolicy discoverEmbedded(AgentConfig config)
      throws PolicyDiscoveryException {
    List<ModulePolicy> policies = new ArrayList<>();
    Map<String, String> moduleToJar = new HashMap<>(); // For duplicate detection

    List<Path> jarPaths = findJarsOnPath();
    LOG.info("Scanning {} JARs for embedded policies", jarPaths.size());

    for (Path jarPath : jarPaths) {
      try (JarFile jarFile = new JarFile(jarPath.toFile(), true)) { // true = verify signatures
        if (!JarSignatureVerifier.hasEmbeddedPolicy(jarFile)) {
          continue;
        }

        // Check signature (unless unsigned allowed)
        if (!config.allowUnsignedPolicies()) {
          if (!JarSignatureVerifier.isSignedAndValid(jarFile)) {
            LOG.warn(
                "Skipping unsigned JAR with embedded policy: {}. "
                    + "Set -Djguard.allowUnsignedPolicies=true for development.",
                jarPath);
            continue;
          }
        } else {
          LOG.debug("Allowing unsigned policy from {} (development mode)", jarPath);
        }

        // Read the embedded policy
        ModulePolicy policy = readEmbeddedPolicy(jarFile);

        // Check for duplicates
        String existingJar = moduleToJar.get(policy.moduleName());
        if (existingJar != null) {
          throw new PolicyDiscoveryException(
              String.format(
                  "Duplicate policy for module '%s' found in:%n  - %s%n  - %s",
                  policy.moduleName(), existingJar, jarPath));
        }

        moduleToJar.put(policy.moduleName(), jarPath.toString());
        policies.add(policy);
        LOG.info(
            "Discovered policy for module '{}' from {} ({} entitlements)",
            policy.moduleName(),
            jarPath.getFileName(),
            policy.entitlements().size());

      } catch (IOException e) {
        LOG.warn("Failed to read JAR {}: {}", jarPath, e.getMessage());
      } catch (SecurityException e) {
        LOG.warn("JAR {} failed signature verification: {}", jarPath, e.getMessage());
      }
    }

    // Add unnamed module policy if configured
    if (config.unnamedModulePolicy() != null) {
      try {
        ModulePolicy unnamedPolicy = readPolicyFile(config.unnamedModulePolicy());

        // Verify it's for the unnamed module
        if (!ApplicationPolicy.UNNAMED_MODULE.equals(unnamedPolicy.moduleName())) {
          LOG.warn(
              "Unnamed module policy file declares module '{}', expected '{}'. Using as-is.",
              unnamedPolicy.moduleName(),
              ApplicationPolicy.UNNAMED_MODULE);
        }

        // Check for duplicates
        String existingJar = moduleToJar.get(unnamedPolicy.moduleName());
        if (existingJar != null) {
          throw new PolicyDiscoveryException(
              String.format(
                  "Duplicate policy for module '%s' found in:%n  - %s%n  - %s (external)",
                  unnamedPolicy.moduleName(), existingJar, config.unnamedModulePolicy()));
        }

        policies.add(unnamedPolicy);
        LOG.info(
            "Loaded unnamed module policy from {} ({} entitlements)",
            config.unnamedModulePolicy(),
            unnamedPolicy.entitlements().size());

      } catch (IOException e) {
        throw new PolicyDiscoveryException(
            "Failed to read unnamed module policy from " + config.unnamedModulePolicy(), e);
      }
    }

    if (policies.isEmpty()) {
      LOG.warn("No embedded policies discovered. All operations will be denied.");
    } else {
      LOG.info(
          "Policy discovery complete: {} module(s), {} total entitlements",
          policies.size(),
          policies.stream().mapToInt(p -> p.entitlements().size()).sum());
    }

    return ApplicationPolicy.create(policies);
  }

  /**
   * Reads an embedded policy from a JAR file.
   *
   * @param jarFile the JAR file containing the policy
   * @return the module policy
   * @throws IOException if the policy cannot be read
   */
  private static ModulePolicy readEmbeddedPolicy(JarFile jarFile) throws IOException {
    JarEntry entry = jarFile.getJarEntry(JarSignatureVerifier.POLICY_LOCATION);
    if (entry == null) {
      throw new IOException("No policy found at " + JarSignatureVerifier.POLICY_LOCATION);
    }

    try (InputStream is = jarFile.getInputStream(entry)) {
      // BinaryPolicyReader.readApplicationPolicy handles both v1 and v2 formats
      ApplicationPolicy appPolicy = BinaryPolicyReader.readApplicationPolicy(is);

      // Embedded policies should contain exactly one module
      if (appPolicy.modules().isEmpty()) {
        throw new IOException("Embedded policy contains no modules");
      }
      if (appPolicy.modules().size() > 1) {
        throw new IOException(
            "Embedded policy contains multiple modules ("
                + appPolicy.modules().size()
                + "). Each JAR should contain policy for one module.");
      }

      return appPolicy.modules().get(0);
    }
  }

  /**
   * Reads a policy from an external file.
   *
   * @param path the path to the policy file
   * @return the module policy
   * @throws IOException if the policy cannot be read
   */
  private static ModulePolicy readPolicyFile(Path path) throws IOException {
    try (InputStream is = Files.newInputStream(path)) {
      ApplicationPolicy appPolicy = BinaryPolicyReader.readApplicationPolicy(is);

      if (appPolicy.modules().isEmpty()) {
        throw new IOException("Policy file contains no modules: " + path);
      }
      if (appPolicy.modules().size() > 1) {
        throw new IOException(
            "Policy file contains multiple modules. Use ApplicationPolicy format for multi-module.");
      }

      return appPolicy.modules().get(0);
    }
  }

  /**
   * Finds all JAR files on the module path and class path.
   *
   * @return list of JAR file paths
   */
  private static List<Path> findJarsOnPath() {
    List<Path> jars = new ArrayList<>();

    // Module path
    String modulePath = System.getProperty("jdk.module.path");
    if (modulePath != null && !modulePath.isBlank()) {
      addJarsFromPath(modulePath, jars);
    }

    // Class path
    String classPath = System.getProperty("java.class.path");
    if (classPath != null && !classPath.isBlank()) {
      addJarsFromPath(classPath, jars);
    }

    return jars;
  }

  /**
   * Adds JAR files from a path string to the list.
   *
   * @param pathString the path string (colon or semicolon separated)
   * @param jars the list to add to
   */
  private static void addJarsFromPath(String pathString, List<Path> jars) {
    String separator = System.getProperty("path.separator", ":");
    String[] entries = pathString.split(separator);

    for (String entry : entries) {
      if (entry.isBlank()) continue;

      Path path = Path.of(entry);
      if (Files.isRegularFile(path) && entry.toLowerCase().endsWith(".jar")) {
        jars.add(path);
      } else if (Files.isDirectory(path)) {
        // Scan directory for JARs
        try (var stream = Files.list(path)) {
          stream
              .filter(p -> p.toString().toLowerCase().endsWith(".jar"))
              .filter(Files::isRegularFile)
              .forEach(jars::add);
        } catch (IOException e) {
          LOG.debug("Failed to scan directory {}: {}", path, e.getMessage());
        }
      }
    }
  }

  /** Exception thrown when policy discovery fails. */
  public static class PolicyDiscoveryException extends Exception {
    private static final long serialVersionUID = 1L;

    public PolicyDiscoveryException(String message) {
      super(message);
    }

    public PolicyDiscoveryException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
