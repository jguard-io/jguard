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
 * ByteBuddy advice for intercepting system property access operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code
 * system.property.read} and {@code system.property.write} capabilities.
 *
 * <p>Instrumented methods:
 *
 * <ul>
 *   <li>{@code System.getProperty(String)} - reads a specific property
 *   <li>{@code System.getProperty(String, String)} - reads a specific property with default
 *   <li>{@code System.getProperties()} - reads all properties (bulk access)
 *   <li>{@code System.setProperty(String, String)} - sets a specific property
 *   <li>{@code System.setProperties(Properties)} - replaces all properties (bulk write)
 *   <li>{@code System.clearProperty(String)} - removes a specific property
 * </ul>
 *
 * <h2>Bulk Access</h2>
 *
 * <p>The {@code System.getProperties()} method returns all system properties. This requires either
 * a no-arg {@code system.property.read} entitlement or a {@code system.property.read("*")}
 * entitlement.
 *
 * <p>The {@code System.setProperties(Properties)} method replaces all system properties. This
 * requires either a no-arg {@code system.property.write} entitlement or a {@code
 * system.property.write("*")} entitlement. Note that {@code setProperties(null)} is also a bulk
 * operation (resets to initial VM properties).
 */
public final class PropertyInterceptor {

  private PropertyInterceptor() {}

  /**
   * Advice for System.getProperty(String) and System.getProperty(String, String).
   *
   * <p>Intercepts access to a specific system property by key.
   */
  public static class GetPropertyAdvice {

    private GetPropertyAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String key) {
      BootstrapEnforcer.onPropertyRead(key);
    }
  }

  /**
   * Advice for System.getProperties() - bulk read.
   *
   * <p>Intercepts bulk system property access. The caller must be entitled to read all system
   * properties (no-arg or "*" pattern).
   */
  public static class GetPropertiesAdvice {

    private GetPropertiesAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter() {
      // null indicates bulk access - requires no-arg or "*" entitlement
      BootstrapEnforcer.onPropertyRead(null);
    }
  }

  /**
   * Advice for System.setProperty(String, String).
   *
   * <p>Intercepts setting a specific system property by key.
   */
  public static class SetPropertyAdvice {

    private SetPropertyAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String key) {
      BootstrapEnforcer.onPropertyWrite(key);
    }
  }

  /**
   * Advice for System.setProperties(Properties) - bulk write.
   *
   * <p>Intercepts bulk system property replacement. The caller must be entitled to write all system
   * properties (no-arg or "*" pattern). Note that setProperties(null) is also a bulk operation.
   */
  public static class SetPropertiesAdvice {

    private SetPropertiesAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter() {
      // null indicates bulk access - requires no-arg or "*" entitlement
      BootstrapEnforcer.onPropertyWrite(null);
    }
  }

  /**
   * Advice for System.clearProperty(String).
   *
   * <p>Intercepts removal of a specific system property by key. Clearing is a write operation.
   */
  public static class ClearPropertyAdvice {

    private ClearPropertyAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String key) {
      BootstrapEnforcer.onPropertyWrite(key);
    }
  }
}
