/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import io.jguard.bootstrap.BootstrapEnforcer;
import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice for intercepting runtime lifecycle operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code runtime.exit}
 * and {@code runtime.shutdown_hook} capabilities.
 *
 * <p>Instrumented methods for {@code runtime.exit}:
 *
 * <ul>
 *   <li>{@code System.exit(int)} - terminates the JVM
 *   <li>{@code Runtime.exit(int)} - terminates the JVM
 *   <li>{@code Runtime.halt(int)} - forcefully terminates the JVM
 * </ul>
 *
 * <p>Instrumented methods for {@code runtime.shutdown_hook}:
 *
 * <ul>
 *   <li>{@code Runtime.addShutdownHook(Thread)} - registers a shutdown hook
 *   <li>{@code Runtime.removeShutdownHook(Thread)} - unregisters a shutdown hook
 * </ul>
 */
public final class RuntimeInterceptor {

  private RuntimeInterceptor() {}

  /**
   * Advice for System.exit(int) and Runtime.exit(int).
   *
   * <p>Intercepts JVM termination requests.
   */
  public static class ExitAdvice {

    private ExitAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) int status) {
      BootstrapEnforcer.onRuntimeExit(status);
    }
  }

  /**
   * Advice for Runtime.halt(int).
   *
   * <p>Intercepts forceful JVM termination.
   */
  public static class HaltAdvice {

    private HaltAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) int status) {
      BootstrapEnforcer.onRuntimeExit(status);
    }
  }

  /**
   * Advice for Runtime.addShutdownHook(Thread) and Runtime.removeShutdownHook(Thread).
   *
   * <p>Intercepts shutdown hook registration and removal.
   */
  public static class ShutdownHookAdvice {

    private ShutdownHookAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) Thread hook) {
      BootstrapEnforcer.onShutdownHook();
    }
  }
}
