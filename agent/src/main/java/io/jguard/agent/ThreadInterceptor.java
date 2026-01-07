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
 * ByteBuddy advice for intercepting thread creation operations.
 *
 * <p>This class contains advice that is woven into JDK thread classes to enforce the {@code
 * threads.create} capability.
 */
public final class ThreadInterceptor {

  private ThreadInterceptor() {}

  /**
   * Advice for Thread.start() method.
   *
   * <p>Intercepts thread startup to check if the caller is entitled to create threads.
   */
  public static class ThreadStartAdvice {

    private ThreadStartAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.This Thread thread) {
      BootstrapEnforcer.onThreadCreate(thread);
    }
  }
}
