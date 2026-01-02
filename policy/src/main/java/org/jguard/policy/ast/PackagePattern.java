/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.ast;

import java.util.List;
import java.util.Objects;

/**
 * A package pattern in an entitlement subject.
 *
 * <p>Patterns have three forms:
 *
 * <ul>
 *   <li>{@code com.example.pkg} - exactly that package
 *   <li>{@code com.example.pkg.*} - direct subpackages only
 *   <li>{@code com.example.pkg..} - package and all descendants
 * </ul>
 *
 * @param segments the package name segments (e.g., ["com", "example", "pkg"])
 * @param matchType the type of matching
 * @param location the source location
 */
public record PackagePattern(List<String> segments, MatchType matchType, SourceLocation location) {

  /** Compact constructor that validates and normalizes the record fields. */
  public PackagePattern {
    Objects.requireNonNull(segments, "segments");
    Objects.requireNonNull(matchType, "matchType");
    Objects.requireNonNull(location, "location");
    segments = List.copyOf(segments);
    if (segments.isEmpty()) {
      throw new IllegalArgumentException("Package pattern must have at least one segment");
    }
  }

  /**
   * Returns the package name as a dot-separated string.
   *
   * @return the package name (e.g., "com.example.pkg")
   */
  public String packageName() {
    return String.join(".", segments);
  }

  @Override
  public String toString() {
    String base = packageName();
    return switch (matchType) {
      case EXACT -> base;
      case DIRECT_SUBPACKAGES -> base + ".*";
      case RECURSIVE -> base + "..";
    };
  }

  /** The type of package matching. */
  public enum MatchType {
    /** Matches exactly the specified package. */
    EXACT,

    /** Matches direct subpackages only (one level). */
    DIRECT_SUBPACKAGES,

    /** Matches the package and all descendant packages. */
    RECURSIVE
  }
}
