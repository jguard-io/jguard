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
 * Policy entitlements for a single JPMS module.
 *
 * <p>This represents the compiled form of a single {@code module-info.jguard} file. In a
 * multi-module application, each module has its own {@code ModulePolicy} containing the
 * entitlements granted to code within that module.
 *
 * @param moduleName the fully qualified JPMS module name (e.g., "com.example.core")
 * @param entitlements the granted entitlements for this module (sorted, deduplicated)
 */
public record ModulePolicy(String moduleName, List<Entitlement> entitlements)
    implements Comparable<ModulePolicy> {

  /** Compact constructor that validates and normalizes the record fields. */
  public ModulePolicy {
    Objects.requireNonNull(moduleName, "moduleName");
    Objects.requireNonNull(entitlements, "entitlements");
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("moduleName cannot be empty");
    }
    // Ensure immutability and sorted order
    entitlements = entitlements.stream().distinct().sorted().toList();
  }

  /**
   * Creates a module policy from a legacy PolicyDescriptor.
   *
   * @param descriptor the legacy single-module policy descriptor
   * @return the module policy
   */
  public static ModulePolicy fromDescriptor(PolicyDescriptor descriptor) {
    return new ModulePolicy(descriptor.moduleName(), descriptor.entitlements());
  }

  @Override
  public int compareTo(ModulePolicy other) {
    return this.moduleName.compareTo(other.moduleName);
  }
}
