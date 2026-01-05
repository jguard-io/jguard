/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import net.bytebuddy.asm.Advice;
import org.jguard.bootstrap.BootstrapEnforcer;

/**
 * ByteBuddy advice for intercepting environment variable access operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code env.read}
 * capability.
 *
 * <p>Instrumented methods:
 *
 * <ul>
 *   <li>{@code System.getenv()} - reads all environment variables (bulk access)
 *   <li>{@code System.getenv(String)} - reads a specific environment variable
 * </ul>
 *
 * <h2>Bulk Access</h2>
 *
 * <p>The no-arg {@code System.getenv()} returns all environment variables. This requires either a
 * no-arg {@code env.read} entitlement or an {@code env.read("*")} entitlement. Specific pattern
 * entitlements like {@code env.read("HOME")} do not grant bulk access.
 */
public final class EnvInterceptor {

  private EnvInterceptor() {}

  /**
   * Advice for System.getenv() - bulk read.
   *
   * <p>Intercepts bulk environment variable access. The caller must be entitled to read all
   * environment variables (no-arg or "*" pattern).
   */
  public static class GetEnvAllAdvice {

    private GetEnvAllAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter() {
      // null indicates bulk access - requires no-arg or "*" entitlement
      BootstrapEnforcer.onEnvRead(null);
    }
  }

  /**
   * Advice for System.getenv(String) - single variable read.
   *
   * <p>Intercepts access to a specific environment variable by name.
   */
  public static class GetEnvAdvice {

    private GetEnvAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String name) {
      BootstrapEnforcer.onEnvRead(name);
    }
  }
}
