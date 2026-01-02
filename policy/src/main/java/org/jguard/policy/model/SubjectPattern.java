/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.model;

import java.util.Comparator;
import java.util.Objects;

/**
 * A subject pattern in an entitlement.
 *
 * <p>Subject patterns specify who is granted a capability:
 *
 * <ul>
 *   <li>The entire module ({@link Type#MODULE})
 *   <li>An exact package ({@link Type#PACKAGE_EXACT})
 *   <li>Direct subpackages ({@link Type#PACKAGE_DIRECT_CHILDREN})
 *   <li>A package and all descendants ({@link Type#PACKAGE_RECURSIVE})
 * </ul>
 *
 * @param type the type of subject pattern
 * @param packageName the package name (null for MODULE type)
 */
public record SubjectPattern(Type type, String packageName) implements Comparable<SubjectPattern> {

  private static final Comparator<SubjectPattern> COMPARATOR =
      Comparator.comparing(SubjectPattern::type)
          .thenComparing(SubjectPattern::packageName, Comparator.nullsFirst(String::compareTo));

  /** Compact constructor that validates the record fields. */
  public SubjectPattern {
    Objects.requireNonNull(type, "type");
    if (type == Type.MODULE && packageName != null) {
      throw new IllegalArgumentException("MODULE type must have null packageName");
    }
    if (type != Type.MODULE && (packageName == null || packageName.isEmpty())) {
      throw new IllegalArgumentException("Package pattern must have a packageName");
    }
  }

  /**
   * Creates a subject pattern for the entire module.
   *
   * @return the module subject pattern
   */
  public static SubjectPattern module() {
    return new SubjectPattern(Type.MODULE, null);
  }

  /**
   * Creates a subject pattern for an exact package.
   *
   * @param packageName the package name
   * @return the subject pattern
   */
  public static SubjectPattern exactPackage(String packageName) {
    return new SubjectPattern(Type.PACKAGE_EXACT, packageName);
  }

  /**
   * Creates a subject pattern for direct subpackages.
   *
   * @param packageName the package name
   * @return the subject pattern
   */
  public static SubjectPattern directChildren(String packageName) {
    return new SubjectPattern(Type.PACKAGE_DIRECT_CHILDREN, packageName);
  }

  /**
   * Creates a subject pattern for a package and all descendants.
   *
   * @param packageName the package name
   * @return the subject pattern
   */
  public static SubjectPattern recursive(String packageName) {
    return new SubjectPattern(Type.PACKAGE_RECURSIVE, packageName);
  }

  /**
   * Returns the canonical string representation for serialization.
   *
   * @return the canonical string
   */
  public String toCanonicalString() {
    return switch (type) {
      case MODULE -> "module";
      case PACKAGE_EXACT -> packageName;
      case PACKAGE_DIRECT_CHILDREN -> packageName + ".*";
      case PACKAGE_RECURSIVE -> packageName + "..";
    };
  }

  @Override
  public int compareTo(SubjectPattern other) {
    return COMPARATOR.compare(this, other);
  }

  @Override
  public String toString() {
    return toCanonicalString();
  }

  /** The type of subject pattern. */
  public enum Type {
    /** The entire module. */
    MODULE,

    /** Exactly the specified package. */
    PACKAGE_EXACT,

    /** Direct children of the specified package. */
    PACKAGE_DIRECT_CHILDREN,

    /** The package and all descendant packages. */
    PACKAGE_RECURSIVE
  }
}
