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
 * @param formatVersion the policy format version (1=single-module, 2=multi-module, 3=with trusted)
 * @param moduleName the fully qualified module name
 * @param entitlements the granted entitlements (sorted, deduplicated)
 * @param denials the denied capabilities (sorted, deduplicated)
 * @param trusted whether this module is trusted (all capability checks bypassed)
 */
public record PolicyDescriptor(
    int formatVersion,
    String moduleName,
    List<Entitlement> entitlements,
    List<Denial> denials,
    boolean trusted) {

  /** Format version 1: single-module policies (legacy). */
  public static final int FORMAT_VERSION_V1 = 1;

  /** Format version 2: multi-module policies with denial support. */
  public static final int FORMAT_VERSION_V2 = 2;

  /** Format version 3: multi-module policies with trusted module support. */
  public static final int FORMAT_VERSION_V3 = 3;

  /** Current format version. */
  public static final int FORMAT_VERSION = FORMAT_VERSION_V3;

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
   * Backwards-compatible constructor for policies without denials or trusted flag.
   *
   * @param formatVersion the format version
   * @param moduleName the module name
   * @param entitlements the entitlements
   */
  public PolicyDescriptor(int formatVersion, String moduleName, List<Entitlement> entitlements) {
    this(formatVersion, moduleName, entitlements, List.of(), false);
  }

  /**
   * Backwards-compatible constructor for policies without trusted flag.
   *
   * @param formatVersion the format version
   * @param moduleName the module name
   * @param entitlements the entitlements
   * @param denials the denials
   */
  public PolicyDescriptor(
      int formatVersion, String moduleName, List<Entitlement> entitlements, List<Denial> denials) {
    this(formatVersion, moduleName, entitlements, denials, false);
  }

  /**
   * Creates a new policy descriptor with the current format version.
   *
   * @param moduleName the fully qualified module name
   * @param entitlements the granted entitlements
   * @return the policy descriptor
   */
  public static PolicyDescriptor create(String moduleName, List<Entitlement> entitlements) {
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements, List.of(), false);
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
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, entitlements, denials, false);
  }

  /**
   * Creates a trusted policy descriptor.
   *
   * @param moduleName the fully qualified module name
   * @return a trusted policy descriptor
   */
  public static PolicyDescriptor trusted(String moduleName) {
    return new PolicyDescriptor(FORMAT_VERSION, moduleName, List.of(), List.of(), true);
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
