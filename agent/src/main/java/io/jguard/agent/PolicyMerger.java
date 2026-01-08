/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.AgentLogger;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.serialization.BinaryPolicyReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Merges embedded policies with external override policies.
 *
 * <p>Policy override semantics are <b>restrictive only</b>:
 *
 * <ul>
 *   <li>Effective policy = embedded ∩ override (intersection)
 *   <li>Overrides can only REMOVE capabilities, never add
 *   <li>An entitlement must exist in both embedded AND override to be effective
 *   <li>Missing override file = full embedded policy applies
 * </ul>
 *
 * <h2>Override Directory Structure</h2>
 *
 * <pre>
 * /etc/myapp/overrides/
 * ├── com.example.core.bin       # Override for com.example.core module
 * ├── com.example.transport.bin  # Override for com.example.transport module
 * └── _global.bin                # Global override (applies to ALL modules)
 * </pre>
 *
 * <h2>Merge Logic</h2>
 *
 * <p>For each module in the embedded policy:
 *
 * <ol>
 *   <li>Start with embedded entitlements
 *   <li>If module-specific override exists, intersect with it
 *   <li>If global override exists, intersect with it
 *   <li>Result = entitlements that exist in ALL applicable policies
 * </ol>
 *
 * <p>This layered approach allows ops teams to restrict capabilities at deployment time without
 * modifying the signed JARs.
 */
public final class PolicyMerger {

  private static final AgentLogger LOG = AgentLogger.getLogger(PolicyMerger.class);

  /** Filename for the global override that applies to all modules. */
  public static final String GLOBAL_OVERRIDE_FILENAME = "_global.bin";

  private PolicyMerger() {}

  /**
   * Merges an embedded policy with overrides from a directory.
   *
   * @param embedded the embedded policy (from signed JARs)
   * @param overrideDir the directory containing override files
   * @return the merged policy with overrides applied
   * @throws IOException if reading override files fails
   */
  public static ApplicationPolicy merge(ApplicationPolicy embedded, Path overrideDir)
      throws IOException {
    if (overrideDir == null || !Files.isDirectory(overrideDir)) {
      LOG.debug("No override directory, using embedded policy as-is");
      return embedded;
    }

    // Load global override if present
    Optional<ModulePolicy> globalOverride = loadOverride(overrideDir, GLOBAL_OVERRIDE_FILENAME);
    if (globalOverride.isPresent()) {
      LOG.info(
          "Loaded global override with {} entitlements",
          globalOverride.get().entitlements().size());
    }

    // Load module-specific overrides
    Map<String, ModulePolicy> moduleOverrides = new HashMap<>();
    for (ModulePolicy module : embedded.modules()) {
      String overrideFilename = module.moduleName() + ".bin";
      Optional<ModulePolicy> override = loadOverride(overrideDir, overrideFilename);
      if (override.isPresent()) {
        moduleOverrides.put(module.moduleName(), override.get());
        LOG.info(
            "Loaded override for module '{}' with {} entitlements",
            module.moduleName(),
            override.get().entitlements().size());
      }
    }

    // If no overrides found, return embedded as-is
    if (globalOverride.isEmpty() && moduleOverrides.isEmpty()) {
      LOG.debug("No override files found in {}, using embedded policy as-is", overrideDir);
      return embedded;
    }

    // Merge each module
    List<ModulePolicy> mergedModules = new ArrayList<>();
    for (ModulePolicy embeddedModule : embedded.modules()) {
      ModulePolicy merged =
          mergeModule(
              embeddedModule,
              moduleOverrides.get(embeddedModule.moduleName()),
              globalOverride.orElse(null));
      mergedModules.add(merged);

      int removedCount = embeddedModule.entitlements().size() - merged.entitlements().size();
      if (removedCount > 0) {
        LOG.info(
            "Module '{}': {} entitlements removed by override ({} -> {})",
            embeddedModule.moduleName(),
            removedCount,
            embeddedModule.entitlements().size(),
            merged.entitlements().size());
      }
    }

    return ApplicationPolicy.create(mergedModules);
  }

  /**
   * Merges a single module's embedded policy with its overrides.
   *
   * @param embedded the embedded module policy
   * @param moduleOverride the module-specific override (may be null)
   * @param globalOverride the global override (may be null)
   * @return the merged module policy
   */
  private static ModulePolicy mergeModule(
      ModulePolicy embedded, ModulePolicy moduleOverride, ModulePolicy globalOverride) {
    Set<Entitlement> effective = new HashSet<>(embedded.entitlements());

    // Apply module-specific override (intersection)
    if (moduleOverride != null) {
      Set<Entitlement> overrideSet = new HashSet<>(moduleOverride.entitlements());
      effective.retainAll(overrideSet);
    }

    // Apply global override (intersection)
    if (globalOverride != null) {
      Set<Entitlement> globalSet = new HashSet<>(globalOverride.entitlements());
      effective.retainAll(globalSet);
    }

    return new ModulePolicy(embedded.moduleName(), new ArrayList<>(effective));
  }

  /**
   * Loads an override policy from a file in the override directory.
   *
   * @param overrideDir the override directory
   * @param filename the override filename
   * @return the loaded policy, or empty if file doesn't exist
   * @throws IOException if reading fails
   */
  private static Optional<ModulePolicy> loadOverride(Path overrideDir, String filename)
      throws IOException {
    Path overridePath = overrideDir.resolve(filename);
    if (!Files.exists(overridePath)) {
      return Optional.empty();
    }

    LOG.debug("Loading override from: {}", overridePath);
    byte[] bytes = Files.readAllBytes(overridePath);
    ApplicationPolicy policy =
        BinaryPolicyReader.readApplicationPolicy(new java.io.ByteArrayInputStream(bytes));

    // Override file should contain exactly one module policy
    if (policy.modules().isEmpty()) {
      LOG.warn("Override file {} is empty, ignoring", filename);
      return Optional.empty();
    }
    if (policy.modules().size() > 1) {
      LOG.warn("Override file {} contains multiple modules, using first", filename);
    }

    return Optional.of(policy.modules().get(0));
  }

  /**
   * Validates that an override policy is a valid subset of the embedded policy.
   *
   * <p>A valid override must only contain entitlements that exist in the embedded policy. This
   * validation catches misconfigurations where an override attempts to grant new capabilities.
   *
   * @param embedded the embedded policy
   * @param override the override policy to validate
   * @return validation result with any invalid entitlements
   */
  public static ValidationResult validateOverride(ModulePolicy embedded, ModulePolicy override) {
    Set<Entitlement> embeddedSet = new HashSet<>(embedded.entitlements());
    List<Entitlement> invalidEntitlements = new ArrayList<>();

    for (Entitlement overrideEnt : override.entitlements()) {
      if (!embeddedSet.contains(overrideEnt)) {
        invalidEntitlements.add(overrideEnt);
      }
    }

    return new ValidationResult(invalidEntitlements.isEmpty(), invalidEntitlements);
  }

  /**
   * Result of override validation.
   *
   * @param valid true if the override is a valid subset of embedded
   * @param invalidEntitlements entitlements in override that don't exist in embedded
   */
  public record ValidationResult(boolean valid, List<Entitlement> invalidEntitlements) {}
}
