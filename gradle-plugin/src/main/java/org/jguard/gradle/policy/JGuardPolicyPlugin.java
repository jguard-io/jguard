/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.gradle.policy;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.file.Directory;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.jvm.tasks.Jar;

/**
 * Gradle plugin that compiles {@code module-info.jguard} policy descriptors and packages them into
 * JAR files.
 *
 * <p>The plugin:
 *
 * <ul>
 *   <li>Registers the {@code jguardPolicy} extension for configuration
 *   <li>Creates a {@code compileJGuardPolicy} task
 *   <li>If the Java plugin is applied, wires the output into the JAR
 * </ul>
 *
 * <p>If the source file does not exist, the task is skipped and nothing is packaged.
 */
public class JGuardPolicyPlugin implements Plugin<Project> {

  public static final String EXTENSION_NAME = "jguardPolicy";
  public static final String TASK_NAME = "compileJGuardPolicy";

  @Override
  public void apply(Project project) {
    // Register extension with convention defaults
    JGuardPolicyExtension extension =
        project.getExtensions().create(EXTENSION_NAME, JGuardPolicyExtension.class);

    configureExtensionDefaults(project, extension);

    // Register the compile task
    TaskProvider<CompileJGuardPolicyTask> compileTask =
        project
            .getTasks()
            .register(
                TASK_NAME,
                CompileJGuardPolicyTask.class,
                task -> {
                  task.setDescription(
                      "Compiles module-info.jguard into policy.bin and optional policy.json");
                  task.setGroup("jguard");

                  // Wire inputs from extension
                  task.getSourceFile().set(extension.getSourceFile());
                  task.getIncludeJson().set(extension.getIncludeJson());

                  // Wire outputs
                  Provider<Directory> outputDir = extension.getOutputDir();
                  task.getOutputBin()
                      .set(outputDir.flatMap(dir -> extension.getBinName().map(dir::file)));
                  task.getOutputJson()
                      .set(
                          extension
                              .getIncludeJson()
                              .flatMap(
                                  include ->
                                      include
                                          ? outputDir.flatMap(
                                              dir -> extension.getJsonName().map(dir::file))
                                          : project.provider(() -> null)));
                });

    // Integrate with jar task if Java plugin is applied
    project
        .getPlugins()
        .withType(
            JavaPlugin.class,
            javaPlugin -> {
              project
                  .getTasks()
                  .named(
                      JavaPlugin.JAR_TASK_NAME,
                      Jar.class,
                      jar -> {
                        jar.dependsOn(compileTask);

                        // Only include outputs if the source file exists
                        jar.from(
                            compileTask.flatMap(
                                task -> {
                                  if (task.getSourceFile().get().getAsFile().exists()) {
                                    return extension.getOutputDir();
                                  }
                                  return project.provider(() -> project.files());
                                }),
                            spec -> {
                              spec.into(extension.getJarPath());
                            });
                      });
            });
  }

  private void configureExtensionDefaults(Project project, JGuardPolicyExtension extension) {
    extension
        .getSourceFile()
        .convention(
            project.getLayout().getProjectDirectory().file("src/main/java/module-info.jguard"));
    extension
        .getOutputDir()
        .convention(project.getLayout().getBuildDirectory().dir("generated/jguard"));
    extension.getIncludeJson().convention(true);
    extension.getBinName().convention("policy.bin");
    extension.getJsonName().convention("policy.json");
    extension.getJarPath().convention("META-INF/jguard");
  }
}
