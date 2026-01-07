/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

/**
 * Determines the calling package for capability checks using StackWalker.
 *
 * <p>This class walks the call stack to find the first frame that belongs to application code
 * (i.e., not JDK, jGuard, ByteBuddy, reflection, or other infrastructure).
 *
 * <p>Note: The primary caller attribution logic is in {@code io.jguard.bootstrap.BootstrapEnforcer}
 * which is used at runtime. This class is maintained for use cases that don't go through the
 * bootstrap path.
 */
public final class CallerAttribution {

  private static final StackWalker WALKER =
      StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

  private CallerAttribution() {
    // Static utility class
  }

  /**
   * Returns the package of the caller that triggered the capability check.
   *
   * <p>Walks the stack to find the first frame that is not part of jGuard, ByteBuddy, JDK
   * infrastructure, reflection, MethodHandles, or synthetic classes (lambdas, proxies).
   *
   * @return the caller's package name, or "unknown" if it cannot be determined
   */
  public static String getCallerPackage() {
    return WALKER
        .walk(
            frames ->
                frames
                    .map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(CallerAttribution::isApplicationCode)
                    .findFirst()
                    .map(Class::getPackageName)
                    .orElse("unknown"))
        .toString();
  }

  /**
   * Returns the class of the caller that triggered the capability check.
   *
   * @return the caller's class, or null if it cannot be determined
   */
  public static Class<?> getCallerClass() {
    return WALKER.walk(
        frames ->
            frames
                .map(StackWalker.StackFrame::getDeclaringClass)
                .filter(CallerAttribution::isApplicationCode)
                .findFirst()
                .orElse(null));
  }

  /**
   * Determines if a class is application code (not infrastructure).
   *
   * <p>This method filters out:
   *
   * <ul>
   *   <li>jGuard infrastructure packages
   *   <li>ByteBuddy packages (original and relocated)
   *   <li>JDK packages (java.*, sun.*, jdk.*)
   *   <li>Reflection infrastructure (java.lang.reflect.*, java.lang.invoke.*)
   *   <li>Lambda classes ($$Lambda$)
   *   <li>Proxy classes ($Proxy)
   * </ul>
   */
  private static boolean isApplicationCode(Class<?> clazz) {
    String name = clazz.getName();

    // Skip jGuard infrastructure packages
    if (name.startsWith("io.jguard.agent.")
        || name.startsWith("io.jguard.bootstrap.")
        || name.startsWith("io.jguard.core.")
        || name.startsWith("io.jguard.policy.")
        || name.startsWith("io.jguard.internal.")) {
      return false;
    }

    // Skip ByteBuddy (both original and relocated)
    if (name.startsWith("net.bytebuddy.")) {
      return false;
    }

    // Skip JDK infrastructure classes
    if (name.startsWith("sun.") || name.startsWith("jdk.") || name.startsWith("java.")) {
      return false;
    }

    // Skip lambda and proxy classes - these are synthetic
    if (name.contains("$$Lambda$") || name.contains(".$Proxy")) {
      return false;
    }

    // Skip reflection and MethodHandle classes
    if (name.startsWith("java.lang.reflect.")
        || name.startsWith("java.lang.invoke.")
        || name.startsWith("jdk.internal.reflect.")) {
      return false;
    }

    return true;
  }
}
