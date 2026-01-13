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
 * @param formatVersion the policy format version (1=single-module, 2=multi-module, 3=with denials)
 * @param moduleName the fully qualified module name
 * @param entitlements the granted entitlements (sorted, deduplicated)
 * @param denials the denied capabilities (sorted, deduplicated)
 */
public record PolicyDescriptor(
    int formatVersion, String moduleName, List<Entitlement> entitlements, List<Denial> denials) {

  /** Format version 1: single-module policies (legacy). */
  public static final int FORMAT_VERSION_V1 = 1;

  /** Format version 2: multi-module policies with denial support. */
  public static final int FORMAT_VERSION_V2 = 2;

  /** Current format version. */
  public static final int FORMAT_VERSION = FORMAT_VERSION_V2;

  /** Compact constructor that validates and normalizes the record fields. */
  public PolicyDescriptor {
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
   * Backwards-compatible constructor for policies without denials.
   *
   * @param formatVersion the format version
   * @param moduleName the module name
   * @param entitlements the entitlements
   */
  public PolicyDescriptor(int formatVersion, String moduleName, List<Entitlement> entitlements) {
    this(formatVersion, moduleName, entitlements, List.of());
  }

  /**
   * Creates a new policy descriptor with the current format version.
   *
   * @param moduleName the fully qualified module name
   * @param entitlements the granted entitlements
   * @return the policy descriptor
   */
  public static PolicyDescriptor create(String moduleName, List<Entitlement> entitlements) {
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements, List.of());
  }

  /**
   * Creates a new policy descriptor with entitlements and denials.
   *
   * @param moduleName the fully qualified module name
   * @param entitlements the granted entitlements
   * @param denials the denied capabilities
   * @return the policy descriptor
   */
  public static PolicyDescriptor create(
      String moduleName, List<Entitlement> entitlements, List<Denial> denials) {
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements, denials);
  }

  /**
   * Returns true if this policy has any denials.
   *
   * @return true if denials exist
   */
  public boolean hasDenials() {
    return !denials.isEmpty();
  }
}
