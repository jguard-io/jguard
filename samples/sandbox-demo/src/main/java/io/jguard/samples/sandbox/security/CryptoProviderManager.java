/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.samples.sandbox.security;

import java.security.Provider;
import java.security.Security;

/**
 * Demonstrates the crypto.provider capability.
 *
 * <p>This class is entitled to modify JCE crypto providers. Without this entitlement, operations
 * like adding or removing providers would result in a SecurityException.
 */
public final class CryptoProviderManager {

  private CryptoProviderManager() {}

  /**
   * Lists all installed security providers.
   *
   * <p>This method does NOT require crypto.provider entitlement as it's read-only.
   *
   * @return array of provider names
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
   * Adds and immediately removes a dummy provider to demonstrate the capability.
   *
   * <p>This method is entitled via: {@code entitle io.jguard.samples.sandbox.security to
   * crypto.provider}
   *
   * @return true if the operation succeeded
   */
  public static boolean demonstrateProviderModification() {
    // Create a dummy provider
    Provider dummyProvider =
        new Provider("DummyProvider", "1.0", "Demonstration provider for jGuard") {
          private static final long serialVersionUID = 1L;
        };

    // Add the provider (requires crypto.provider entitlement)
    int position = Security.addProvider(dummyProvider);
    if (position == -1) {
      return false; // Provider already exists
    }

    // Remove the provider (also requires crypto.provider entitlement)
    Security.removeProvider("DummyProvider");

    return true;
  }

  /**
   * Gets the value of a security property.
   *
   * <p>This method does NOT require crypto.provider entitlement as getProperty is read-only.
   *
   * @param key the property key
   * @return the property value, or null if not set
   */
  public static String getSecurityProperty(String key) {
    return Security.getProperty(key);
  }

  /**
   * Sets a security property.
   *
   * <p>This method requires crypto.provider entitlement.
   *
   * @param key the property key
   * @param value the property value
   */
  public static void setSecurityProperty(String key, String value) {
    Security.setProperty(key, value);
  }
}
