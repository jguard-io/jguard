/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.core;

/**
 * Main entry point for jGuard runtime.
 *
 * <p>This class provides access to the jGuard security enforcement system.
 */
public final class JGuard {

  private JGuard() {
    // Static utility class
  }

  /** Returns the jGuard runtime version. */
  public static String version() {
    return "0.1.0-SNAPSHOT";
  }
}
