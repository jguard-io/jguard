/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.ast;

import java.util.List;
import java.util.Objects;

/**
 * The root AST node for a jGuard policy descriptor file.
 *
 * <p>A policy file contains exactly one security module declaration.
 *
 * @param moduleName the module name segments (e.g., ["org", "jguard", "samples"])
 * @param entitlements the entitlement declarations
 * @param denials the deny declarations
 * @param trusted whether this module is marked as trusted (all capability checks bypassed)
 * @param location the source location of the 'security' keyword
 */
public record PolicyFile(
    List<String> moduleName,
    List<EntitlementDeclaration> entitlements,
    List<DenyDeclaration> denials,
    boolean trusted,
    SourceLocation location) {

  /** Compact constructor that validates and normalizes the record fields. */
  public PolicyFile {
    Objects.requireNonNull(moduleName, "moduleName");
    Objects.requireNonNull(entitlements, "entitlements");
    Objects.requireNonNull(denials, "denials");
    Objects.requireNonNull(location, "location");
    moduleName = List.copyOf(moduleName);
    entitlements = List.copyOf(entitlements);
    denials = List.copyOf(denials);
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("Module name must have at least one segment");
    }
  }

  /**
   * Backwards-compatible constructor for policy files without denials and not trusted.
   *
   * @param moduleName the module name segments
   * @param entitlements the entitlement declarations
   * @param location the source location
   */
  public PolicyFile(
      List<String> moduleName, List<EntitlementDeclaration> entitlements, SourceLocation location) {
    this(moduleName, entitlements, List.of(), false, location);
  }

  /**
   * Backwards-compatible constructor for policy files without trusted flag.
   *
   * @param moduleName the module name segments
   * @param entitlements the entitlement declarations
   * @param denials the deny declarations
   * @param location the source location
   */
  public PolicyFile(
      List<String> moduleName,
      List<EntitlementDeclaration> entitlements,
      List<DenyDeclaration> denials,
      SourceLocation location) {
    this(moduleName, entitlements, denials, false, location);
  }

  /**
   * Returns the module name as a dot-separated string.
   *
   * @return the module name (e.g., "io.jguard.samples")
   */
  public String moduleNameString() {
    return String.join(".", moduleName);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("security module ").append(moduleNameString()).append(" {\n");
    if (trusted) {
      sb.append("    trusted;\n");
    }
    for (EntitlementDeclaration e : entitlements) {
      sb.append("    ").append(e).append("\n");
    }
    for (DenyDeclaration d : denials) {
      sb.append("    ").append(d).append("\n");
    }
    sb.append("}");
    return sb.toString();
  }
}
