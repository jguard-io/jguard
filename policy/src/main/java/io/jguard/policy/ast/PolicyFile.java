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
 * @param location the source location of the 'security' keyword
 */
public record PolicyFile(
    List<String> moduleName, List<EntitlementDeclaration> entitlements, SourceLocation location) {

  /** Compact constructor that validates and normalizes the record fields. */
  public PolicyFile {
    Objects.requireNonNull(moduleName, "moduleName");
    Objects.requireNonNull(entitlements, "entitlements");
    Objects.requireNonNull(location, "location");
    moduleName = List.copyOf(moduleName);
    entitlements = List.copyOf(entitlements);
    if (moduleName.isEmpty()) {
      throw new IllegalArgumentException("Module name must have at least one segment");
    }
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
    for (EntitlementDeclaration e : entitlements) {
      sb.append("    ").append(e).append("\n");
    }
    sb.append("}");
    return sb.toString();
  }
}
