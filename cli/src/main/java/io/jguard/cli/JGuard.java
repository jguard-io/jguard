/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * jGuard CLI - Policy inspection and validation tools.
 *
 * <p>For compiling policies, use {@code jguardc}.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard inspect mymodule.jar
 * jguard list --module-path libs/
 * jguard diff embedded.bin override.bin
 * jguard validate-override --jar mymodule.jar --override override.bin
 * </pre>
 */
@Command(
    name = "jguard",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.JGuard.class,
    description = "jGuard policy inspection and validation tools",
    subcommands = {
      InspectCommand.class,
      ListCommand.class,
      DiffCommand.class,
      ValidateOverrideCommand.class,
      CommandLine.HelpCommand.class
    })
public final class JGuard {

  public static void main(String[] args) {
    int exitCode = new CommandLine(new JGuard()).execute(args);
    System.exit(exitCode);
  }
}
