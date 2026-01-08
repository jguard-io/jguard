/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * Validate that an override policy is a valid subset of the embedded policy.
 *
 * <p>A valid override must only contain entitlements that exist in the embedded policy. This
 * catches misconfigurations where an override attempts to grant new capabilities.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard validate-override --jar mymodule.jar --override override.bin
 * jguard validate-override --embedded embedded.bin --override override.bin
 * </pre>
 */
@Command(
    name = "validate-override",
    mixinStandardHelpOptions = true,
    description = "Validate that an override policy is a valid subset of the embedded policy")
public final class ValidateOverrideCommand implements Callable<Integer> {

  /** Standard location for embedded policies in JARs. */
  private static final String EMBEDDED_POLICY_PATH = "META-INF/jguard/policy.bin";

  @Spec private CommandSpec spec;

  @Option(
      names = {"--jar"},
      description = "Path to JAR file containing the embedded policy")
  private Path jarPath;

  @Option(
      names = {"--embedded"},
      description = "Path to embedded policy file (alternative to --jar)")
  private Path embeddedPath;

  @Option(
      names = {"--override"},
      description = "Path to override policy file",
      required = true)
  private Path overridePath;

  @Override
  public Integer call() {
    PrintWriter out = spec.commandLine().getOut();
    PrintWriter err = spec.commandLine().getErr();

    // Validate arguments
    if (jarPath == null && embeddedPath == null) {
      err.println("Error: Either --jar or --embedded is required");
      return 1;
    }
    if (jarPath != null && embeddedPath != null) {
      err.println("Error: Cannot specify both --jar and --embedded");
      return 1;
    }

    try {
      // Load embedded policy
      ApplicationPolicy embedded;
      if (jarPath != null) {
        embedded = loadFromJar(jarPath, err);
      } else {
        embedded = loadPolicy(embeddedPath, err);
      }

      if (embedded == null) {
        return 1;
      }

      // Load override policy
      ApplicationPolicy override = loadPolicy(overridePath, err);
      if (override == null) {
        return 1;
      }

      // Validate each module in the override
      boolean valid = true;
      for (ModulePolicy overrideModule : override.modules()) {
        ModulePolicy embeddedModule = embedded.getModule(overrideModule.moduleName()).orElse(null);

        if (embeddedModule == null) {
          err.println("Error: Override references unknown module: " + overrideModule.moduleName());
          valid = false;
          continue;
        }

        // Check each entitlement in override exists in embedded
        List<Entitlement> invalidEntitlements =
            validateEntitlements(embeddedModule, overrideModule);

        if (!invalidEntitlements.isEmpty()) {
          err.println(
              "Error: Override for module '"
                  + overrideModule.moduleName()
                  + "' contains "
                  + invalidEntitlements.size()
                  + " entitlement(s) not in embedded policy:");
          for (Entitlement ent : invalidEntitlements) {
            err.println("  - " + formatEntitlement(ent));
          }
          valid = false;
        }
      }

      if (valid) {
        out.println("Override is valid (all entitlements are subsets of embedded policy).");
        out.println("  Embedded modules: " + embedded.modules().size());
        out.println("  Override modules: " + override.modules().size());
        return 0;
      } else {
        err.println();
        err.println("Override validation FAILED.");
        err.println("Overrides can only RESTRICT capabilities, not grant new ones.");
        return 1;
      }
    } catch (IOException e) {
      err.println("Error: " + e.getMessage());
      return 1;
    }
  }

  private ApplicationPolicy loadFromJar(Path path, PrintWriter err) throws IOException {
    if (!Files.exists(path)) {
      err.println("Error: JAR file not found: " + path);
      return null;
    }

    try (JarFile jar = new JarFile(path.toFile())) {
      JarEntry entry = jar.getJarEntry(EMBEDDED_POLICY_PATH);
      if (entry == null) {
        err.println("Error: No embedded policy found in JAR: " + path);
        return null;
      }

      try (InputStream is = jar.getInputStream(entry)) {
        return BinaryPolicyReader.readApplicationPolicy(is);
      }
    }
  }

  private ApplicationPolicy loadPolicy(Path path, PrintWriter err) throws IOException {
    if (!Files.exists(path)) {
      err.println("Error: File not found: " + path);
      return null;
    }

    try (InputStream is = Files.newInputStream(path)) {
      return BinaryPolicyReader.readApplicationPolicy(is);
    } catch (Exception e) {
      // Try v1 format
      try {
        PolicyDescriptor descriptor = BinaryPolicyReader.fromFile(path);
        return ApplicationPolicy.fromDescriptor(descriptor);
      } catch (Exception e2) {
        err.println("Error reading policy from " + path + ": " + e.getMessage());
        return null;
      }
    }
  }

  private List<Entitlement> validateEntitlements(ModulePolicy embedded, ModulePolicy override) {
    Set<Entitlement> embeddedSet = new HashSet<>(embedded.entitlements());
    return override.entitlements().stream().filter(ent -> !embeddedSet.contains(ent)).toList();
  }

  private String formatEntitlement(Entitlement ent) {
    StringBuilder sb = new StringBuilder();
    sb.append(ent.subject()).append(" -> ").append(ent.capability().name());
    if (!ent.capability().arguments().isEmpty()) {
      sb.append("(");
      for (int i = 0; i < ent.capability().arguments().size(); i++) {
        if (i > 0) sb.append(", ");
        sb.append(ent.capability().arguments().get(i));
      }
      sb.append(")");
    }
    return sb.toString();
  }
}
