/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.nativelib;

/**
 * Native library loader entitled to load native libraries.
 *
 * <p>This class is in the {@code io.jguard.samples.sandbox.nativelib} package, which is entitled
 * to {@code native.load} capability.
 */
public final class NativeLoader {

  private NativeLoader() {
    // Static utility class
  }

  /**
   * Attempts to load a native library.
   *
   * <p>This method is entitled to native.load because it's in the .nativelib package.
   *
   * @param libraryName the name of the library to load
   * @throws UnsatisfiedLinkError if the library cannot be found
   * @throws SecurityException if not entitled to native.load (when agent is active)
   */
  public static void tryLoadLibrary(String libraryName) {
    System.loadLibrary(libraryName);
  }

  /**
   * Attempts to load a native library by path.
   *
   * <p>This method is entitled to native.load because it's in the .nativelib package.
   *
   * @param libraryPath the full path to the library
   * @throws UnsatisfiedLinkError if the library cannot be loaded
   * @throws SecurityException if not entitled to native.load (when agent is active)
   */
  public static void tryLoad(String libraryPath) {
    System.load(libraryPath);
  }
}
