/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.gradle.policy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.stream.Collectors;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.SkipWhenEmpty;
import org.gradle.api.tasks.TaskAction;
import org.jguard.policy.compiler.CompilationResult;
import org.jguard.policy.compiler.PolicyCompiler;

/**
 * Task that compiles a {@code module-info.jguard} descriptor into binary and optional JSON formats.
 *
 * <p>This task delegates to {@link PolicyCompiler} from the {@code :policy} module. If the source
 * file does not exist, the task is skipped.
 */
public abstract class CompileJGuardPolicyTask extends DefaultTask {

  /** The source policy descriptor file. Task is skipped if this file does not exist. */
  @InputFile
  @SkipWhenEmpty
  @PathSensitive(PathSensitivity.RELATIVE)
  public abstract RegularFileProperty getSourceFile();

  /** The output binary policy file. */
  @OutputFile
  public abstract RegularFileProperty getOutputBin();

  /** The output JSON policy file (optional). */
  @OutputFile
  @Optional
  public abstract RegularFileProperty getOutputJson();

  /** Whether to generate JSON output. */
  @Input
  public abstract Property<Boolean> getIncludeJson();

  @TaskAction
  public void compile() throws IOException {
    Path sourcePath = getSourceFile().get().getAsFile().toPath();
    Path binPath = getOutputBin().get().getAsFile().toPath();
    Path jsonPath =
        getIncludeJson().get() && getOutputJson().isPresent()
            ? getOutputJson().get().getAsFile().toPath()
            : null;

    getLogger().info("Compiling jGuard policy: {} -> {}", sourcePath, binPath);

    CompilationResult result = PolicyCompiler.compile(sourcePath, binPath, jsonPath);

    if (result.isFailure()) {
      String errors =
          result.diagnostics().stream()
              .map(CompilationResult.Diagnostic::toString)
              .collect(Collectors.joining("\n"));
      throw new GradleException("jGuard policy compilation failed:\n" + errors);
    }

    if (jsonPath != null) {
      getLogger().info("Generated JSON policy: {}", jsonPath);
    }
  }
}
