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
 * The canonical, deterministic representation of a jGuard policy.
 *
 * <p>This is the compiled form of a {@code module-info.jguard} file. It is normalized and sorted to
 * ensure that identical source files produce byte-identical output.
 *
 * @param formatVersion the policy format version (always 1 for now)
 * @param moduleName the fully qualified module name
 * @param entitlements the granted entitlements (sorted, deduplicated)
 */
public record PolicyDescriptor(
    int formatVersion, String moduleName, List<Entitlement> entitlements) {

  public static final int FORMAT_VERSION = 1;

  /** Compact constructor that validates and normalizes the record fields. */
  public PolicyDescriptor {
    Objects.requireNonNull(moduleName, "moduleName");
    Objects.requireNonNull(entitlements, "entitlements");
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("moduleName cannot be empty");
    }
    // Ensure immutability and sorted order
    entitlements = entitlements.stream().distinct().sorted().toList();
  }

  /**
   * Creates a new policy descriptor with format version 1.
   *
   * @param moduleName the fully qualified module name
   * @param entitlements the granted entitlements
   * @return the policy descriptor
   */
  public static PolicyDescriptor create(String moduleName, List<Entitlement> entitlements) {
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements);
  }
}
