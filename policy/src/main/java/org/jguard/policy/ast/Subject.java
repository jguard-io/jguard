/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.ast;

/**
 * The subject of an entitlement declaration.
 *
 * <p>A subject is either the entire module or a package pattern.
 */
public sealed interface Subject permits Subject.Module, Subject.Package {

  /** Returns the source location of this subject. */
  SourceLocation location();

  /** The entire module as a subject. */
  record Module(SourceLocation location) implements Subject {
    @Override
    public String toString() {
      return "module";
    }
  }

  /** A package pattern as a subject. */
  record Package(PackagePattern pattern, SourceLocation location) implements Subject {
    @Override
    public String toString() {
      return pattern.toString();
    }
  }
}
