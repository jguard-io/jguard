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
 * A deny declaration in a security module.
 *
 * <p>Syntax: {@code deny <subject> to <capability>;} or {@code deny(defensive) <subject> to
 * <capability>;}
 *
 * <p>The {@code defensive} modifier suppresses warnings when the denied capability was never
 * granted.
 *
 * @param subject the subject being denied the capability
 * @param capability the capability being denied
 * @param defensive true if this is a defensive denial (suppresses warning if capability not
 *     granted)
 * @param location the source location of the 'deny' keyword
 */
public record DenyDeclaration(
    Subject subject, Capability capability, boolean defensive, SourceLocation location) {

  /** Compact constructor that validates the record fields. */
  public DenyDeclaration {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(capability, "capability");
    Objects.requireNonNull(location, "location");
  }

  @Override
  public String toString() {
    if (defensive) {
      return "deny(defensive) " + subject + " to " + capability + ";";
    }
    return "deny " + subject + " to " + capability + ";";
  }
}
