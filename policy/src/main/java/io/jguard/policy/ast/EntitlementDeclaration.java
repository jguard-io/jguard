/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.ast;

import java.util.Objects;

/**
 * An entitlement declaration in a security module.
 *
 * <p>Syntax: {@code entitle <subject> to <capability>;}
 *
 * @param subject the subject being granted the capability
 * @param capability the capability being granted
 * @param location the source location of the 'entitle' keyword
 */
public record EntitlementDeclaration(
    Subject subject, Capability capability, SourceLocation location) {

  /** Compact constructor that validates the record fields. */
  public EntitlementDeclaration {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(capability, "capability");
    Objects.requireNonNull(location, "location");
  }

  @Override
  public String toString() {
    return "entitle " + subject + " to " + capability + ";";
  }
}
