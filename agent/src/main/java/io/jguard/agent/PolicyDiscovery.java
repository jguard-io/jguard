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
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Discovers embedded jGuard policies from JARs and directories on the module/class path.
 *
 * <p>This class scans for policies at:
 *
 * <ul>
 *   <li>{@code META-INF/jguard/policy.bin} - Embedded policy for the module itself
 *   <li>{@code META-INF/jguard/external/*.bin} - External policies for third-party libraries
 * </ul>
 *
 * <p>Both JAR files (production) and directories (development/testing) are scanned.
 *
 * <h2>External Policies</h2>
 *
 * <p>External policies allow modules to ship policies for their runtime dependencies (e.g., Netty,
 * Reactor, Jackson) that don't have native jGuard support. When a module's JAR contains external
 * policies, they are automatically discovered and applied to the named modules.
 *
 * <h2>Security Model</h2>
 *
 * <p>By default, policies are only loaded from signed JARs. This prevents malicious unsigned code
 * from granting itself capabilities. The {@code jguard.allowUnsignedPolicies} system property can
 * be set to {@code true} for development/testing. Directory-based policies always require this flag
 * since directories cannot be signed.
 *
 * <h2>Duplicate Detection</h2>
 *
 * <p>If two entries contain policies for the same module name, discovery fails with a clear error.
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
    Map<String, String> moduleToSource = new HashMap<>(); // For duplicate detection

    // Scan JAR files
    List<Path> jarPaths = findJarsOnPath();
    LOG.info("Scanning {} JARs for embedded policies", jarPaths.size());
    discoverFromJars(config, jarPaths, policies, moduleToSource);

    // Scan directory entries (for development/testing with Gradle class directories)
    List<Path> dirPaths = findDirectoriesOnPath();
    if (!dirPaths.isEmpty()) {
      LOG.info("Scanning {} directories for embedded policies", dirPaths.size());
      discoverFromDirectories(config, dirPaths, policies, moduleToSource);
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
        String existingSource = moduleToSource.get(unnamedPolicy.moduleName());
        if (existingSource != null) {
          throw new PolicyDiscoveryException(
              String.format(
                  "Duplicate policy for module '%s' found in:%n  - %s%n  - %s (external)",
                  unnamedPolicy.moduleName(), existingSource, config.unnamedModulePolicy()));
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

      // Log all discovered modules at debug level
      LOG.debug("Discovered modules:");
      for (ModulePolicy mp : policies) {
        LOG.debug(
            "  - {} ({} entitlements, trusted={})",
            mp.moduleName(),
            mp.entitlements().size(),
            mp.trusted());
      }
    }

    return ApplicationPolicy.create(policies);
  }

  /**
   * Discovers policies from JAR files.
   *
   * <p>This method scans each JAR for:
   *
   * <ul>
   *   <li>Embedded policy at {@code META-INF/jguard/policy.bin}
   *   <li>External policies at {@code META-INF/jguard/external/*.bin}
   * </ul>
   *
   * @param config the agent configuration
   * @param jarPaths the JAR files to scan
   * @param policies the list to add discovered policies to
   * @param moduleToSource map for duplicate detection
   * @throws PolicyDiscoveryException if a duplicate module is found
   */
  private static void discoverFromJars(
      AgentConfig config,
      List<Path> jarPaths,
      List<ModulePolicy> policies,
      Map<String, String> moduleToSource)
      throws PolicyDiscoveryException {

    LOG.debug("Starting JAR scan for embedded and external policies");
    LOG.debug("allowUnsignedPolicies={}", config.allowUnsignedPolicies());

    for (Path jarPath : jarPaths) {
      try (JarFile jarFile = new JarFile(jarPath.toFile(), true)) { // true = verify signatures
        boolean hasEmbedded = JarSignatureVerifier.hasEmbeddedPolicy(jarFile);
        List<String> externalEntries = JarSignatureVerifier.findExternalPolicyEntries(jarFile);

        if (!hasEmbedded && externalEntries.isEmpty()) {
          continue;
        }

        LOG.debug(
            "JAR {} has policies: embedded={}, external={}",
            jarPath.getFileName(),
            hasEmbedded,
            externalEntries.size());
        if (!externalEntries.isEmpty()) {
          LOG.debug("External policy entries in {}: {}", jarPath.getFileName(), externalEntries);
        }

        // Check signature (unless unsigned allowed)
        boolean isSignedJar = true;
        if (!config.allowUnsignedPolicies()) {
          if (!JarSignatureVerifier.hasSignatures(jarFile)) {
            if (hasEmbedded) {
              LOG.warn(
                  "Skipping unsigned JAR with embedded policy: {}. "
                      + "Set -Djguard.allowUnsignedPolicies=true for development.",
                  jarPath);
            }
            if (!externalEntries.isEmpty()) {
              LOG.warn(
                  "Skipping {} external policies from unsigned JAR: {}. "
                      + "Set -Djguard.allowUnsignedPolicies=true for development.",
                  externalEntries.size(),
                  jarPath);
            }
            continue;
          }
          isSignedJar = true;
        } else {
          LOG.debug(
              "Allowing unsigned policies from {} (development mode, allowUnsignedPolicies=true)",
              jarPath.getFileName());
          isSignedJar = false;
        }

        LOG.debug(
            "Processing {} policies from {}: isSignedJar={}",
            hasEmbedded ? "embedded" : "" + (!externalEntries.isEmpty() ? " + external" : ""),
            jarPath.getFileName(),
            isSignedJar);

        // Discover embedded policy
        if (hasEmbedded) {
          // Verify signature on the embedded policy entry
          if (isSignedJar && !config.allowUnsignedPolicies()) {
            if (!JarSignatureVerifier.isEntrySigned(
                jarFile, JarSignatureVerifier.POLICY_LOCATION)) {
              LOG.warn("JAR {} embedded policy entry is not signed", jarPath);
              continue;
            }
          }

          ModulePolicy policy = readEmbeddedPolicy(jarFile);

          // Check for duplicates
          String existingSource = moduleToSource.get(policy.moduleName());
          if (existingSource != null) {
            throw new PolicyDiscoveryException(
                String.format(
                    "Duplicate policy for module '%s' found in:%n  - %s%n  - %s",
                    policy.moduleName(), existingSource, jarPath));
          }

          moduleToSource.put(policy.moduleName(), jarPath.toString());
          policies.add(policy);
          LOG.info(
              "Discovered policy for module '{}' from {} ({} entitlements)",
              policy.moduleName(),
              jarPath.getFileName(),
              policy.entitlements().size());
        }

        // Discover external policies
        LOG.debug(
            "Processing {} external policy entries from {}",
            externalEntries.size(),
            jarPath.getFileName());
        for (String entryName : externalEntries) {
          LOG.debug("Reading external policy entry: {}", entryName);

          // Verify signature on each external policy entry
          if (isSignedJar && !config.allowUnsignedPolicies()) {
            if (!JarSignatureVerifier.isEntrySigned(jarFile, entryName)) {
              LOG.warn("JAR {} external policy entry {} is not signed", jarPath, entryName);
              continue;
            }
          }

          ModulePolicy policy = readExternalPolicy(jarFile, entryName);
          LOG.debug(
              "Read external policy: module='{}', entitlements={}, trusted={}",
              policy.moduleName(),
              policy.entitlements().size(),
              policy.trusted());

          // Check for duplicates
          String existingSource = moduleToSource.get(policy.moduleName());
          if (existingSource != null) {
            throw new PolicyDiscoveryException(
                String.format(
                    "Duplicate policy for module '%s' found in:%n  - %s%n  - %s (external)",
                    policy.moduleName(), existingSource, jarPath));
          }

          moduleToSource.put(policy.moduleName(), jarPath.toString() + "!" + entryName);
          policies.add(policy);
          LOG.info(
              "Discovered external policy for module '{}' from {} ({} entitlements)",
              policy.moduleName(),
              jarPath.getFileName(),
              policy.entitlements().size());
        }

      } catch (IOException e) {
        LOG.warn("Failed to read JAR {}: {}", jarPath, e.getMessage());
      } catch (SecurityException e) {
        LOG.warn("JAR {} failed signature verification: {}", jarPath, e.getMessage());
      }
    }
  }

  /**
   * Reads an external policy from a JAR file.
   *
   * @param jarFile the JAR file containing the policy
   * @param entryName the name of the entry (e.g., META-INF/jguard/external/io.netty.common.bin)
   * @return the module policy
   * @throws IOException if the policy cannot be read
   */
  private static ModulePolicy readExternalPolicy(JarFile jarFile, String entryName)
      throws IOException {
    JarEntry entry = jarFile.getJarEntry(entryName);
    if (entry == null) {
      throw new IOException("No policy found at " + entryName);
    }

    try (InputStream is = jarFile.getInputStream(entry)) {
      ApplicationPolicy appPolicy = BinaryPolicyReader.readApplicationPolicy(is);

      // External policies should contain exactly one module
      if (appPolicy.modules().isEmpty()) {
        throw new IOException("External policy contains no modules: " + entryName);
      }
      if (appPolicy.modules().size() > 1) {
        throw new IOException(
            "External policy contains multiple modules ("
                + appPolicy.modules().size()
                + "). Each file should contain policy for one module: "
                + entryName);
      }

      return appPolicy.modules().get(0);
    }
  }

  /**
   * Discovers policies from directory entries on the classpath.
   *
   * <p>This supports development/testing scenarios where Gradle outputs compiled policies to class
   * directories rather than JARs. Both embedded policies ({@code META-INF/jguard/policy.bin}) and
   * external policies ({@code META-INF/jguard/external/*.bin}) are discovered.
   *
   * @param config the agent configuration
   * @param dirPaths the directories to scan
   * @param policies the list to add discovered policies to
   * @param moduleToSource map for duplicate detection
   * @throws PolicyDiscoveryException if a duplicate module is found
   */
  private static void discoverFromDirectories(
      AgentConfig config,
      List<Path> dirPaths,
      List<ModulePolicy> policies,
      Map<String, String> moduleToSource)
      throws PolicyDiscoveryException {

    LOG.debug("Starting directory scan for embedded and external policies");
    LOG.debug(
        "Scanning {} directories, allowUnsignedPolicies={}",
        dirPaths.size(),
        config.allowUnsignedPolicies());

    for (Path dirPath : dirPaths) {
      LOG.debug("Checking directory: {}", dirPath);
      // Directory-based policies require allowUnsignedPolicies since directories can't be signed
      if (!config.allowUnsignedPolicies()) {
        Path policyFile = dirPath.resolve(JarSignatureVerifier.POLICY_LOCATION);
        Path externalDir = dirPath.resolve(JarSignatureVerifier.EXTERNAL_POLICIES_DIR);
        if (Files.exists(policyFile) || Files.isDirectory(externalDir)) {
          LOG.warn(
              "Skipping directory-based policies at {}. "
                  + "Set -Djguard.allowUnsignedPolicies=true for development.",
              dirPath);
        }
        continue;
      }

      // Discover embedded policy
      Path policyFile = dirPath.resolve(JarSignatureVerifier.POLICY_LOCATION);
      if (Files.exists(policyFile)) {
        try {
          ModulePolicy policy = readPolicyFromDirectory(policyFile);

          // Check for duplicates
          String existingSource = moduleToSource.get(policy.moduleName());
          if (existingSource != null) {
            throw new PolicyDiscoveryException(
                String.format(
                    "Duplicate policy for module '%s' found in:%n  - %s%n  - %s",
                    policy.moduleName(), existingSource, dirPath));
          }

          moduleToSource.put(policy.moduleName(), dirPath.toString());
          policies.add(policy);
          LOG.info(
              "Discovered policy for module '{}' from directory {} ({} entitlements)",
              policy.moduleName(),
              dirPath,
              policy.entitlements().size());

        } catch (IOException e) {
          LOG.warn("Failed to read policy from directory {}: {}", dirPath, e.getMessage());
        }
      }

      // Discover external policies
      Path externalDir = dirPath.resolve(JarSignatureVerifier.EXTERNAL_POLICIES_DIR);
      LOG.debug(
          "Checking for external policies at: {} (exists={})",
          externalDir,
          Files.isDirectory(externalDir));
      if (Files.isDirectory(externalDir)) {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(externalDir, "*.bin")) {
          for (Path externalPolicyFile : stream) {
            LOG.debug("Found external policy file: {}", externalPolicyFile);
            try {
              ModulePolicy policy = readPolicyFromDirectory(externalPolicyFile);

              // Check for duplicates
              String existingSource = moduleToSource.get(policy.moduleName());
              if (existingSource != null) {
                throw new PolicyDiscoveryException(
                    String.format(
                        "Duplicate policy for module '%s' found in:%n  - %s%n  - %s (external)",
                        policy.moduleName(), existingSource, externalPolicyFile));
              }

              moduleToSource.put(policy.moduleName(), externalPolicyFile.toString());
              policies.add(policy);
              LOG.info(
                  "Discovered external policy for module '{}' from directory {} ({} entitlements)",
                  policy.moduleName(),
                  externalPolicyFile.getFileName(),
                  policy.entitlements().size());

            } catch (IOException e) {
              LOG.warn(
                  "Failed to read external policy from {}: {}", externalPolicyFile, e.getMessage());
            }
          }
        } catch (IOException e) {
          LOG.warn(
              "Failed to scan external policies directory {}: {}", externalDir, e.getMessage());
        }
      }
    }
  }

  /**
   * Reads an embedded policy from a directory (for development/testing).
   *
   * @param policyFile the path to the policy.bin file
   * @return the module policy
   * @throws IOException if the policy cannot be read
   */
  private static ModulePolicy readPolicyFromDirectory(Path policyFile) throws IOException {
    try (InputStream is = Files.newInputStream(policyFile)) {
      ApplicationPolicy appPolicy = BinaryPolicyReader.readApplicationPolicy(is);

      // Embedded policies should contain exactly one module
      if (appPolicy.modules().isEmpty()) {
        throw new IOException("Policy file contains no modules: " + policyFile);
      }
      if (appPolicy.modules().size() > 1) {
        throw new IOException(
            "Policy file contains multiple modules ("
                + appPolicy.modules().size()
                + "). Each directory should contain policy for one module: "
                + policyFile);
      }

      return appPolicy.modules().get(0);
    }
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

  /**
   * Finds all directories on the module path and class path.
   *
   * <p>This supports development/testing scenarios where classes are in directories rather than
   * JARs (e.g., Gradle's {@code build/classes/java/main}).
   *
   * @return list of directory paths
   */
  private static List<Path> findDirectoriesOnPath() {
    List<Path> dirs = new ArrayList<>();

    // Module path
    String modulePath = System.getProperty("jdk.module.path");
    if (modulePath != null && !modulePath.isBlank()) {
      addDirectoriesFromPath(modulePath, dirs);
    }

    // Class path
    String classPath = System.getProperty("java.class.path");
    if (classPath != null && !classPath.isBlank()) {
      addDirectoriesFromPath(classPath, dirs);
    }

    return dirs;
  }

  /**
   * Adds directories from a path string to the list.
   *
   * @param pathString the path string (colon or semicolon separated)
   * @param dirs the list to add to
   */
  private static void addDirectoriesFromPath(String pathString, List<Path> dirs) {
    String separator = System.getProperty("path.separator", ":");
    String[] entries = pathString.split(separator);

    for (String entry : entries) {
      if (entry.isBlank()) continue;

      Path path = Path.of(entry);
      if (Files.isDirectory(path)) {
        // Only add if it's directly a class directory (not a directory containing JARs)
        // We look for directories that might contain META-INF/jguard/policy.bin
        dirs.add(path);
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
