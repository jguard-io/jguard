/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import io.jguard.Version;
import picocli.CommandLine.IVersionProvider;

/** Version providers for CLI commands. */
public final class VersionProvider {

  private VersionProvider() {}

  /** Version provider for the jguard CLI. */
  public static class JGuard implements IVersionProvider {
    @Override
    public String[] getVersion() {
      return new String[] {"jguard " + Version.VERSION};
    }
  }

  /** Version provider for the jguardc compiler. */
  public static class JGuardc implements IVersionProvider {
    @Override
    public String[] getVersion() {
      return new String[] {"jguardc " + Version.VERSION};
    }
  }
}
