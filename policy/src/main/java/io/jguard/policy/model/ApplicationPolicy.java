/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Complete policy for a multi-module application.
 *
 * <p>An {@code ApplicationPolicy} aggregates the policies of all JPMS modules in an application.
 * Each module has its own {@link ModulePolicy} containing entitlements for code within that module.
 *
 * <p>This is the v2 policy format that supports multi-module applications. For backward
 * compatibility, single-module v1 policies are automatically wrapped into an ApplicationPolicy with
 * one module.
 *
 * @param formatVersion the policy format version (2 for multi-module)
 * @param modules the policies for each module, indexed by module name
 */
public record ApplicationPolicy(int formatVersion, List<ModulePolicy> modules) {

  /** Format version for multi-module policies. */
  public static final int FORMAT_VERSION = 2;

  /** Special module name for unnamed module (classpath code). */
  public static final String UNNAMED_MODULE = "unnamed";

  /** Compact constructor that validates and normalizes the record fields. */
  public ApplicationPolicy {
    Objects.requireNonNull(modules, "modules");
    // Ensure immutability and sorted order
    modules = modules.stream().distinct().sorted().toList();

    // Validate no duplicate module names
    Map<String, ModulePolicy> seen = new HashMap<>();
    for (ModulePolicy module : modules) {
      ModulePolicy existing = seen.put(module.moduleName(), module);
      if (existing != null) {
        throw new IllegalArgumentException("Duplicate module policy for: " + module.moduleName());
      }
    }
  }

  /**
   * Creates a new application policy.
   *
   * @param modules the module policies
   * @return the application policy
   */
  public static ApplicationPolicy create(List<ModulePolicy> modules) {
    return new ApplicationPolicy(FORMAT_VERSION, modules);
  }

  /**
   * Creates an application policy from a single module policy.
   *
   * @param module the single module policy
   * @return the application policy containing just that module
   */
  public static ApplicationPolicy single(ModulePolicy module) {
    return new ApplicationPolicy(FORMAT_VERSION, List.of(module));
  }

  /**
   * Creates an application policy from a legacy PolicyDescriptor.
   *
   * <p>This enables backward compatibility with v1 single-module policies.
   *
   * @param descriptor the legacy single-module policy descriptor
   * @return the application policy containing that module
   */
  public static ApplicationPolicy fromDescriptor(PolicyDescriptor descriptor) {
    return single(ModulePolicy.fromDescriptor(descriptor));
  }

  /**
   * Looks up the policy for a specific module.
   *
   * @param moduleName the JPMS module name
   * @return the module policy, or empty if no policy exists for that module
   */
  public Optional<ModulePolicy> getModule(String moduleName) {
    for (ModulePolicy module : modules) {
      if (module.moduleName().equals(moduleName)) {
        return Optional.of(module);
      }
    }
    return Optional.empty();
  }

  /**
   * Checks if this application policy contains a policy for the given module.
   *
   * @param moduleName the JPMS module name
   * @return true if a policy exists for the module
   */
  public boolean hasModule(String moduleName) {
    return getModule(moduleName).isPresent();
  }

  /**
   * Returns the total number of entitlements across all modules.
   *
   * @return the total entitlement count
   */
  public int totalEntitlementCount() {
    return modules.stream().mapToInt(m -> m.entitlements().size()).sum();
  }
}
