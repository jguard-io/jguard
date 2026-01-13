/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.gradle.policy;

import io.jguard.policy.compiler.CompilationResult;
import io.jguard.policy.compiler.PolicyCompiler;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.SkipWhenEmpty;
import org.gradle.api.tasks.TaskAction;

/**
 * Task that compiles external policy {@code .jguard} files to binary format.
 *
 * <p>This task processes all {@code *.jguard} files in the input directory and compiles each to a
 * corresponding {@code *.bin} file in the output directory. The output filename is derived from the
 * input filename (e.g., {@code _global.jguard} becomes {@code _global.bin}).
 *
 * <p>External policies are used to grant or deny capabilities at deployment time without modifying
 * module source code. See the jGuard documentation for details on external policy semantics.
 */
public abstract class CompileExternalPoliciesTask extends DefaultTask {

  /** The source directory containing {@code .jguard} files. Task is skipped if empty. */
  @InputDirectory
  @SkipWhenEmpty
  @PathSensitive(PathSensitivity.RELATIVE)
  public abstract DirectoryProperty getSourceDir();

  /** The output directory for compiled {@code .bin} files. */
  @OutputDirectory
  public abstract DirectoryProperty getOutputDir();

  /** Whether to also generate JSON output for debugging. */
  @Input
  @Optional
  public abstract Property<Boolean> getIncludeJson();

  @TaskAction
  public void compile() throws IOException {
    File sourceDir = getSourceDir().get().getAsFile();
    File outputDir = getOutputDir().get().getAsFile();
    boolean includeJson = getIncludeJson().getOrElse(false);

    // Ensure output directory exists
    Files.createDirectories(outputDir.toPath());

    // Find all .jguard files
    List<Path> sourceFiles;
    try (Stream<Path> files = Files.list(sourceDir.toPath())) {
      sourceFiles =
          files.filter(p -> p.toString().endsWith(".jguard")).collect(Collectors.toList());
    }

    if (sourceFiles.isEmpty()) {
      getLogger().lifecycle("No .jguard files found in {}", sourceDir);
      return;
    }

    getLogger()
        .lifecycle("Compiling {} external policy file(s) from {}", sourceFiles.size(), sourceDir);

    List<String> errors = new ArrayList<>();

    for (Path sourceFile : sourceFiles) {
      String baseName = sourceFile.getFileName().toString();
      baseName = baseName.substring(0, baseName.length() - ".jguard".length());

      Path binPath = outputDir.toPath().resolve(baseName + ".bin");
      Path jsonPath = includeJson ? outputDir.toPath().resolve(baseName + ".json") : null;

      getLogger().info("  {} -> {}", sourceFile.getFileName(), binPath.getFileName());

      try {
        CompilationResult result = PolicyCompiler.compile(sourceFile, binPath, jsonPath);

        if (result.isFailure()) {
          String fileErrors =
              result.diagnostics().stream()
                  .map(CompilationResult.Diagnostic::toString)
                  .collect(Collectors.joining("\n  "));
          errors.add(sourceFile.getFileName() + ":\n  " + fileErrors);
        }
      } catch (IOException e) {
        errors.add(sourceFile.getFileName() + ": " + e.getMessage());
      }
    }

    if (!errors.isEmpty()) {
      throw new GradleException(
          "External policy compilation failed:\n" + String.join("\n", errors));
    }

    getLogger()
        .lifecycle("Compiled {} external policy file(s) to {}", sourceFiles.size(), outputDir);
  }
}
