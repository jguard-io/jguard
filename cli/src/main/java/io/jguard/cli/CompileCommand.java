/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import io.jguard.policy.compiler.CompilationResult;
import io.jguard.policy.compiler.PolicyCompiler;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/**
 * Compile jGuard policy descriptors.
 *
 * <p>Usage:
 *
 * <pre>
 * jguard compile -o policy.bin module-info.jguard
 * jguard compile -o policy.bin --json policy.json module-info.jguard
 * </pre>
 */
@Command(
    name = "compile",
    mixinStandardHelpOptions = true,
    description = "Compile a module-info.jguard source file to binary format")
public final class CompileCommand implements Callable<Integer> {

  @Spec private CommandSpec spec;

  @Parameters(index = "0", description = "Path to the module-info.jguard source file")
  private Path source;

  @Option(
      names = {"-o", "--output"},
      description = "Output path for the compiled binary policy file",
      required = true)
  private Path output;

  @Option(
      names = {"--json"},
      description = "Also output JSON format to the specified path")
  private Path jsonOutput;

  @Option(
      names = {"-v", "--verbose"},
      description = "Enable verbose output")
  private boolean verbose;

  @Override
  public Integer call() {
    PrintWriter err = spec.commandLine().getErr();

    if (verbose) {
      err.println("jguard: compiling " + source);
    }

    try {
      CompilationResult result = PolicyCompiler.compile(source, output, jsonOutput);

      if (result.isSuccess()) {
        if (verbose) {
          err.println("jguard: wrote " + output);
          if (jsonOutput != null) {
            err.println("jguard: wrote " + jsonOutput);
          }
        }
        return 0;
      } else {
        for (CompilationResult.Diagnostic diagnostic : result.diagnostics()) {
          printDiagnostic(err, diagnostic);
        }
        return 1;
      }
    } catch (IOException e) {
      err.println("jguard: " + e.getMessage());
      if (verbose) {
        e.printStackTrace(err);
      }
      return 1;
    }
  }

  private void printDiagnostic(PrintWriter err, CompilationResult.Diagnostic diagnostic) {
    StringBuilder sb = new StringBuilder();

    // Format: path:line:column: severity: message (gcc/clang style)
    if (diagnostic.sourcePath() != null) {
      sb.append(diagnostic.sourcePath());
      if (diagnostic.line() > 0) {
        sb.append(":").append(diagnostic.line());
        if (diagnostic.column() > 0) {
          sb.append(":").append(diagnostic.column());
        }
      }
      sb.append(": ");
    }

    sb.append(diagnostic.severity().name().toLowerCase());
    sb.append(": ");
    sb.append(diagnostic.message());

    err.println(sb);
  }
}
