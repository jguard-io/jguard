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
 * jGuard CLI - Policy management and inspection tools.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard compile -o policy.bin module-info.jguard
 * jguard inspect mymodule.jar
 * jguard list --module-path libs/
 * jguard diff embedded.bin override.bin
 * jguard validate-override --jar mymodule.jar --override override.bin
 * </pre>
 */
@Command(
    name = "jguard",
    mixinStandardHelpOptions = true,
    version = "jguard 0.2.0",
    description = "jGuard policy management and inspection tools",
    subcommands = {
      CompileCommand.class,
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
