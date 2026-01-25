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
 * ByteBuddy advice for intercepting crypto provider operations.
 *
 * <p>This class contains advice that is woven into JDK classes to enforce the {@code
 * crypto.provider} capability.
 *
 * <p>Instrumented methods:
 *
 * <ul>
 *   <li>{@code Security.addProvider(Provider)} - adds a security provider
 *   <li>{@code Security.insertProviderAt(Provider, int)} - inserts provider at position
 *   <li>{@code Security.removeProvider(String)} - removes a provider
 *   <li>{@code Security.setProperty(String, String)} - sets security property
 * </ul>
 *
 * <p>Note: {@code Security.getProperty()} is not guarded as it is read-only and does not pose a
 * security risk.
 */
public final class SecurityInterceptor {

  private SecurityInterceptor() {}

  /**
   * Advice for crypto provider modification operations.
   *
   * <p>Intercepts all provider modification operations to check if the caller is entitled to modify
   * crypto providers.
   */
  public static class ProviderModificationAdvice {

    private ProviderModificationAdvice() {}

    @Advice.OnMethodEnter
    public static void onEnter() {
      BootstrapEnforcer.onCryptoProvider();
    }
  }
}
