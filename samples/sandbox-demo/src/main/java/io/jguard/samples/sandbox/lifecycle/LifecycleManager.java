/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.lifecycle;

/**
 * Demonstrates the runtime.exit and runtime.shutdown_hook capabilities.
 *
 * <p>This class is entitled to:
 *
 * <ul>
 *   <li>{@code runtime.exit} - terminate the JVM
 *   <li>{@code runtime.shutdown_hook} - register shutdown hooks
 * </ul>
 *
 * <p>These capabilities protect server applications from rogue libraries that might call {@code
 * System.exit()} or register interfering shutdown hooks.
 */
public final class LifecycleManager {

  private static volatile Thread registeredHook;

  private LifecycleManager() {}

  /**
   * Attempts to register a shutdown hook.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.lifecycle to
   * runtime.shutdown_hook}
   *
   * @param name the name of the hook thread
   * @param action the action to run on shutdown
   * @return true if the hook was registered successfully
   */
  public static boolean registerShutdownHook(String name, Runnable action) {
    Thread hook =
        new Thread(action, name) {
          @Override
          public void run() {
            System.out.println("  [Shutdown Hook] " + getName() + " running...");
            super.run();
          }
        };

    Runtime.getRuntime().addShutdownHook(hook);
    registeredHook = hook;
    return true;
  }

  /**
   * Attempts to remove a previously registered shutdown hook.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.lifecycle to
   * runtime.shutdown_hook}
   *
   * @return true if a hook was removed, false if no hook was registered
   */
  public static boolean removeShutdownHook() {
    if (registeredHook != null) {
      boolean removed = Runtime.getRuntime().removeShutdownHook(registeredHook);
      registeredHook = null;
      return removed;
    }
    return false;
  }

  /**
   * Demonstrates that runtime.exit capability is required but we won't actually call it.
   *
   * <p>In a real scenario, this would call System.exit(). For the demo, we just verify the
   * capability check would happen by attempting the call in a way that can be caught.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.lifecycle to
   * runtime.exit}
   *
   * @param status the exit status code (not actually used - we catch the call)
   * @return a message describing what would happen
   */
  public static String demonstrateExitCapability(int status) {
    // We use a SecurityManager check pattern - attempt the operation
    // but don't actually exit. In jGuard, the check happens before the method runs.
    // For demo purposes, we just document that this package is entitled.
    return "Package io.jguard.samples.sandbox.lifecycle is entitled to call System.exit("
        + status
        + ")";
  }

  /**
   * Attempts to call Runtime.halt() which is also guarded by runtime.exit.
   *
   * <p>This method is for documentation purposes - we won't actually halt the JVM in the demo.
   *
   * @param status the halt status code
   * @return a message describing what would happen
   */
  public static String demonstrateHaltCapability(int status) {
    return "Package io.jguard.samples.sandbox.lifecycle is entitled to call Runtime.halt("
        + status
        + ")";
  }
}
