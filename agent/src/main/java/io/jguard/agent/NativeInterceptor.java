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
 * ByteBuddy advice for intercepting native library loading operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code native.load}
 * capability.
 *
 * <p>Instrumented methods:
 *
 * <ul>
 *   <li>{@code System.loadLibrary(String)} - loads library from java.library.path
 *   <li>{@code System.load(String)} - loads library from absolute path
 *   <li>{@code Runtime.loadLibrary(String)} - delegates to System.loadLibrary
 *   <li>{@code Runtime.load(String)} - delegates to System.load
 * </ul>
 */
public final class NativeInterceptor {

  private NativeInterceptor() {}

  /**
   * Advice for System.loadLibrary() and Runtime.loadLibrary().
   *
   * <p>Intercepts library loading by name to check if the caller is entitled to load native
   * libraries.
   */
  public static class LoadLibraryAdvice {

    private LoadLibraryAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String libname) {
      BootstrapEnforcer.onNativeLoad(libname);
    }
  }

  /**
   * Advice for System.load() and Runtime.load().
   *
   * <p>Intercepts library loading by absolute path to check if the caller is entitled to load
   * native libraries.
   */
  public static class LoadAdvice {

    private LoadAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String filename) {
      BootstrapEnforcer.onNativeLoad(filename);
    }
  }
}
