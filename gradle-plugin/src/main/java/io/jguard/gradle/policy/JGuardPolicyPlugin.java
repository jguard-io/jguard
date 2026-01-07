/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.gradle.policy;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.file.Directory;
import org.gradle.api.plugins.ApplicationPlugin;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.JavaExec;
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
  public static final String AGENT_CONFIGURATION_NAME = "jguardAgent";
  public static final String RUN_WITH_AGENT_TASK_NAME = "runWithAgent";

  @Override
  public void apply(Project project) {
    // Register extension with convention defaults
    JGuardPolicyExtension extension =
        project.getExtensions().create(EXTENSION_NAME, JGuardPolicyExtension.class);

    configureExtensionDefaults(project, extension);

    // Create the jguardAgent configuration for the agent dependency
    Configuration agentConfig = createAgentConfiguration(project);

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

    // Register runWithAgent task when application plugin is applied
    project
        .getPlugins()
        .withType(
            ApplicationPlugin.class,
            appPlugin -> registerRunWithAgentTask(project, extension, compileTask, agentConfig));
  }

  private Configuration createAgentConfiguration(Project project) {
    return project
        .getConfigurations()
        .create(
            AGENT_CONFIGURATION_NAME,
            config -> {
              config.setDescription("jGuard agent JAR for runtime enforcement");
              config.setCanBeConsumed(false);
              config.setCanBeResolved(true);
              config.setVisible(false);
            });
  }

  private void registerRunWithAgentTask(
      Project project,
      JGuardPolicyExtension extension,
      TaskProvider<CompileJGuardPolicyTask> compileTask,
      Configuration agentConfig) {

    // Get the run task provider lazily
    TaskProvider<JavaExec> runTaskProvider =
        project.getTasks().named(ApplicationPlugin.TASK_RUN_NAME, JavaExec.class);

    project
        .getTasks()
        .register(
            RUN_WITH_AGENT_TASK_NAME,
            JavaExec.class,
            task -> {
              task.setDescription("Run the application with jGuard agent enforcement enabled");
              task.setGroup("application");
              task.dependsOn(compileTask);

              // Wire main class and module from the run task using providers (lazy)
              task.getMainClass().set(runTaskProvider.flatMap(JavaExec::getMainClass));
              task.getMainModule().set(runTaskProvider.flatMap(JavaExec::getMainModule));

              // Classpath must be set after evaluation
              task.setClasspath(project.files(runTaskProvider.map(JavaExec::getClasspath)));

              // Configure JVM arguments with agent
              task.doFirst(
                  t -> {
                    // Check if skipped via property
                    if (project.hasProperty("jguard.skip")
                        && "true".equals(project.property("jguard.skip"))) {
                      project.getLogger().lifecycle("jGuard agent skipped via -Pjguard.skip=true");
                      return;
                    }

                    // Find the agent JAR
                    File agentJar = findAgentJar(project, agentConfig);
                    if (agentJar == null) {
                      throw new IllegalStateException(
                          "jGuard agent JAR not found. Add it to the '"
                              + AGENT_CONFIGURATION_NAME
                              + "' configuration:\n"
                              + "  dependencies {\n"
                              + "    jguardAgent(\"io.jguard:agent:VERSION\")\n"
                              + "  }");
                    }

                    // Get policy file
                    File policyFile = compileTask.get().getOutputBin().get().getAsFile();
                    if (!policyFile.exists()) {
                      throw new IllegalStateException(
                          "Policy file not found: "
                              + policyFile
                              + ". Run 'compileJGuardPolicy' first.");
                    }

                    // Build JVM args
                    List<String> jvmArgs = new ArrayList<>(task.getJvmArgs());
                    jvmArgs.add(
                        "-javaagent:"
                            + agentJar.getAbsolutePath()
                            + "="
                            + policyFile.getAbsolutePath());

                    // Add mode from property or extension
                    String mode =
                        getPropertyOrExtension(project, "jguard.mode", extension.getMode());
                    if (mode != null) {
                      jvmArgs.add("-Djguard.mode=" + mode);
                    }

                    // Add log level from extension
                    String logLevel = extension.getLogLevel().getOrNull();
                    if (logLevel != null) {
                      jvmArgs.add("-Djguard.log.level=" + logLevel);
                    }

                    task.setJvmArgs(jvmArgs);

                    project.getLogger().lifecycle("Running with jGuard agent...");
                    project.getLogger().lifecycle("  Agent: " + agentJar);
                    project.getLogger().lifecycle("  Policy: " + policyFile);
                    if (mode != null) {
                      project.getLogger().lifecycle("  Mode: " + mode);
                    }
                  });
            });
  }

  private File findAgentJar(Project project, Configuration agentConfig) {
    // First check the configuration
    if (!agentConfig.isEmpty()) {
      return agentConfig.getSingleFile();
    }

    // For composite builds, look for the jguard included build
    // This handles the case where the agent is built locally
    for (var includedBuild : project.getGradle().getIncludedBuilds()) {
      if ("jguard".equals(includedBuild.getName())) {
        File agentLibsDir = new File(includedBuild.getProjectDir(), "agent/build/libs");
        File[] agentJars =
            agentLibsDir.listFiles(
                (dir, name) ->
                    name.startsWith("jguard-agent-")
                        && name.endsWith(".jar")
                        && !name.contains("-sources")
                        && !name.contains("-javadoc"));
        if (agentJars != null && agentJars.length > 0) {
          return agentJars[0];
        }
        break;
      }
    }

    // Fall back to looking relative to the project (for standalone builds)
    File[] agentJars =
        new File(project.getRootDir(), "../jguard/agent/build/libs")
            .listFiles(
                (dir, name) ->
                    name.startsWith("jguard-agent-")
                        && name.endsWith(".jar")
                        && !name.contains("-sources")
                        && !name.contains("-javadoc"));
    if (agentJars != null && agentJars.length > 0) {
      return agentJars[0];
    }

    return null;
  }

  private String getPropertyOrExtension(
      Project project, String propertyName, Provider<String> extensionValue) {
    if (project.hasProperty(propertyName)) {
      return (String) project.property(propertyName);
    }
    return extensionValue.getOrNull();
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
    extension.getMode().convention("strict");
    extension.getLogLevel().convention("info");
  }
}
