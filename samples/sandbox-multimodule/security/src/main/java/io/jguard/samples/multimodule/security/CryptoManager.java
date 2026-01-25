/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.multimodule.security;

import java.security.Provider;
import java.security.Security;

/**
 * Demonstrates the crypto.provider capability.
 *
 * <p>This class is entitled to modify JCE crypto providers. Without this entitlement, operations
 * like adding or removing providers would result in a SecurityException.
 *
 * <p>Note: This class is in a package containing "security" to demonstrate that jGuard supports
 * contextual keywords in package names.
 */
public final class CryptoManager {

  private CryptoManager() {}

  /**
   * Lists all installed security providers.
   *
   * @return array of provider info strings
   */
  public static String[] listProviders() {
    Provider[] providers = Security.getProviders();
    String[] names = new String[providers.length];
    for (int i = 0; i < providers.length; i++) {
      names[i] = providers[i].getName() + " v" + providers[i].getVersionStr();
    }
    return names;
  }

  /**
   * Adds and immediately removes a test provider to demonstrate the capability.
   *
   * @return result message
   */
  public static String demonstrateProviderModification() {
    try {
      Provider testProvider =
          new Provider("JGuardTestProvider", "1.0", "Test provider for jGuard demo") {
            private static final long serialVersionUID = 1L;
          };

      int position = Security.addProvider(testProvider);
      if (position == -1) {
        return "Provider already exists";
      }

      Security.removeProvider("JGuardTestProvider");
      return "Successfully added and removed test provider at position " + position;
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    }
  }

  /**
   * Sets a security property.
   *
   * @param key the property key
   * @param value the property value
   * @return result message
   */
  public static String setSecurityProperty(String key, String value) {
    try {
      Security.setProperty(key, value);
      return "Successfully set " + key + "=" + value;
    } catch (SecurityException e) {
      return "BLOCKED: " + e.getMessage();
    }
  }
}
