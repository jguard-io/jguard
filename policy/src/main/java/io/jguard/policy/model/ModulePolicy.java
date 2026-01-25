/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.model;

import java.util.List;
import java.util.Objects;

/**
 * Policy entitlements and denials for a single JPMS module.
 *
 * <p>This represents the compiled form of a single {@code module-info.jguard} file. In a
 * multi-module application, each module has its own {@code ModulePolicy} containing the
 * entitlements and denials for code within that module.
 *
 * <p>A module may be marked as {@code trusted}, in which case all capability checks are bypassed
 * for code within that module. This is intended as an escape hatch for native libraries (e.g.,
 * PyTorch) that require unrestricted access. Trusted modules can only be declared in external
 * policy override files, not in embedded policies.
 *
 * @param moduleName the fully qualified JPMS module name (e.g., "com.example.core")
 * @param entitlements the granted entitlements for this module (sorted, deduplicated)
 * @param denials the denied capabilities for this module (sorted, deduplicated)
 * @param trusted whether this module is trusted (all capability checks bypassed)
 */
public record ModulePolicy(
    String moduleName, List<Entitlement> entitlements, List<Denial> denials, boolean trusted)
    implements Comparable<ModulePolicy> {

  /** Compact constructor that validates and normalizes the record fields. */
  public ModulePolicy {
    Objects.requireNonNull(moduleName, "moduleName");
    Objects.requireNonNull(entitlements, "entitlements");
    Objects.requireNonNull(denials, "denials");
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("moduleName cannot be empty");
    }
    // Ensure immutability and sorted order
    entitlements = entitlements.stream().distinct().sorted().toList();
    denials = denials.stream().distinct().sorted().toList();
  }

  /**
   * Backwards-compatible constructor for policies without denials or trusted flag.
   *
   * @param moduleName the module name
   * @param entitlements the entitlements
   */
  public ModulePolicy(String moduleName, List<Entitlement> entitlements) {
    this(moduleName, entitlements, List.of(), false);
  }

  /**
   * Backwards-compatible constructor for policies without trusted flag.
   *
   * @param moduleName the module name
   * @param entitlements the entitlements
   * @param denials the denials
   */
  public ModulePolicy(String moduleName, List<Entitlement> entitlements, List<Denial> denials) {
    this(moduleName, entitlements, denials, false);
  }

  /**
   * Creates a trusted module policy.
   *
   * <p>A trusted module bypasses all capability checks. This is intended for native libraries that
   * require unrestricted access (e.g., PyTorch, TensorFlow).
   *
   * <p><b>Security Warning:</b> Trusted modules have full access to all operations. Only use this
   * for well-vetted native code that cannot function with restricted permissions.
   *
   * @param moduleName the module name
   * @return a trusted module policy
   */
  public static ModulePolicy trusted(String moduleName) {
    return new ModulePolicy(moduleName, List.of(), List.of(), true);
  }

  /**
   * Creates a module policy from a PolicyDescriptor.
   *
   * @param descriptor the policy descriptor
   * @return the module policy
   */
  public static ModulePolicy fromDescriptor(PolicyDescriptor descriptor) {
    return new ModulePolicy(
        descriptor.moduleName(), descriptor.entitlements(), descriptor.denials(), false);
  }

  /**
   * Returns true if this module policy has any denials.
   *
   * @return true if denials exist
   */
  public boolean hasDenials() {
    return !denials.isEmpty();
  }

  @Override
  public int compareTo(ModulePolicy other) {
    return this.moduleName.compareTo(other.moduleName);
  }
}
