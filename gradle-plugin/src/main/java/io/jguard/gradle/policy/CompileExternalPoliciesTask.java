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
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.IgnoreEmptyDirectories;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Internal;
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

  /**
   * The source directory containing {@code .jguard} files.
   *
   * <p>This is used as a reference for the source location. The actual input tracking is done via
   * {@link #getSourceFiles()}.
   */
  @Internal
  public abstract DirectoryProperty getSourceDir();

  /**
   * The source {@code .jguard} files to compile.
   *
   * <p>This property tracks the actual file contents for up-to-date checking. Configure this with
   * the source directory's file tree filtered to {@code *.jguard} files.
   */
  @InputFiles
  @SkipWhenEmpty
  @IgnoreEmptyDirectories
  @PathSensitive(PathSensitivity.RELATIVE)
  public abstract ConfigurableFileCollection getSourceFiles();

  /** The output directory for compiled {@code .bin} files. */
  @OutputDirectory
  public abstract DirectoryProperty getOutputDir();

  /** Whether to also generate JSON output for debugging. */
  @Input
  @Optional
  public abstract Property<Boolean> getIncludeJson();

  @TaskAction
  public void compile() throws IOException {
    File outputDir = getOutputDir().get().getAsFile();
    boolean includeJson = getIncludeJson().getOrElse(false);

    // Ensure output directory exists
    Files.createDirectories(outputDir.toPath());

    // Get source files from the tracked input collection
    List<File> sourceFiles =
        getSourceFiles().getFiles().stream()
            .filter(f -> f.getName().endsWith(".jguard"))
            .collect(Collectors.toList());

    if (sourceFiles.isEmpty()) {
      getLogger().lifecycle("No .jguard files to compile");
      return;
    }

    getLogger().lifecycle("Compiling {} external policy file(s)", sourceFiles.size());

    List<String> errors = new ArrayList<>();

    for (File sourceFile : sourceFiles) {
      String baseName = sourceFile.getName();
      baseName = baseName.substring(0, baseName.length() - ".jguard".length());

      Path binPath = outputDir.toPath().resolve(baseName + ".bin");
      Path jsonPath = includeJson ? outputDir.toPath().resolve(baseName + ".json") : null;

      getLogger().info("  {} -> {}", sourceFile.getName(), binPath.getFileName());

      try {
        CompilationResult result = PolicyCompiler.compile(sourceFile.toPath(), binPath, jsonPath);

        if (result.isFailure()) {
          String fileErrors =
              result.diagnostics().stream()
                  .map(CompilationResult.Diagnostic::toString)
                  .collect(Collectors.joining("\n  "));
          errors.add(sourceFile.getName() + ":\n  " + fileErrors);
        }
      } catch (IOException e) {
        errors.add(sourceFile.getName() + ": " + e.getMessage());
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
