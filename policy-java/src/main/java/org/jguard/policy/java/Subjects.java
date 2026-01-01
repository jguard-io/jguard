/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.java;

import org.jguard.policy.model.SubjectPattern;

/**
 * Factory methods for creating subject patterns.
 *
 * <p>This class provides type-safe, IDE-friendly methods for defining entitlement subjects in Java
 * code. Use with static imports for a clean DSL:
 *
 * <pre>{@code
 * import static org.jguard.policy.java.Subjects.*;
 *
 * grant(module(), networkOutbound());           // Entire module
 * grant(pkg("com.example"), fsRead(...));       // Exact package
 * grant(pkgChildren("com.example"), ...);       // Direct children (com.example.*)
 * grant(pkgRecursive("com.example"), ...);      // All descendants (com.example..)
 * }</pre>
 *
 * <p>All subject methods validate package names at construction time.
 */
public final class Subjects {

  private Subjects() {
    // Static factory class
  }

  /**
   * Creates a module subject pattern.
   *
   * <p>This grants the capability to the entire module (all packages).
   *
   * @return the subject pattern
   */
  public static SubjectPattern module() {
    return SubjectPattern.module();
  }

  /**
   * Creates an exact package subject pattern.
   *
   * <p>This grants the capability only to code in the specified package (not subpackages).
   *
   * @param packageName the fully qualified package name (e.g., "com.example.net")
   * @return the subject pattern
   */
  public static SubjectPattern pkg(String packageName) {
    validatePackageName(packageName);
    return SubjectPattern.exactPackage(packageName);
  }

  /**
   * Creates a direct children package subject pattern.
   *
   * <p>This grants the capability to direct child packages only (equivalent to {@code
   * com.example.*} in the policy DSL).
   *
   * @param packageName the parent package name (e.g., "com.example")
   * @return the subject pattern
   */
  public static SubjectPattern pkgChildren(String packageName) {
    validatePackageName(packageName);
    return SubjectPattern.directChildren(packageName);
  }

  /**
   * Creates a recursive package subject pattern.
   *
   * <p>This grants the capability to the package and all descendant packages (equivalent to {@code
   * com.example..} in the policy DSL).
   *
   * @param packageName the root package name (e.g., "com.example")
   * @return the subject pattern
   */
  public static SubjectPattern pkgRecursive(String packageName) {
    validatePackageName(packageName);
    return SubjectPattern.recursive(packageName);
  }

  // ===== Validation =====

  private static void validatePackageName(String packageName) {
    if (packageName == null) {
      throw new IllegalArgumentException("Package name cannot be null");
    }
    if (packageName.isEmpty()) {
      throw new IllegalArgumentException("Package name cannot be empty");
    }
    // Basic validation - more thorough checks happen in SubjectPattern
    if (packageName.startsWith(".") || packageName.endsWith(".")) {
      throw new IllegalArgumentException("Invalid package name: " + packageName);
    }
  }
}
