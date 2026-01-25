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
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.provider.Provider;
import org.gradle.api.tasks.JavaExec;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.TaskProvider;
import org.gradle.api.tasks.compile.JavaCompile;
import org.gradle.api.tasks.testing.Test;
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
  public static final String EXTERNAL_POLICIES_TASK_NAME = "compileExternalPolicies";
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

    // Register the external policies compile task (only if source dir is configured)
    project
        .getTasks()
        .register(
            EXTERNAL_POLICIES_TASK_NAME,
            CompileExternalPoliciesTask.class,
            task -> {
              task.setDescription(
                  "Compiles external policy .jguard files from the configured directory");
              task.setGroup("jguard");

              // Wire inputs from extension
              task.getSourceDir().set(extension.getExternalPoliciesSourceDir());
              task.getOutputDir().set(extension.getExternalPoliciesOutputDir());
              task.getIncludeJson().set(extension.getExternalPoliciesIncludeJson());

              // Only enable task if source dir is configured
              task.onlyIf(
                  t -> {
                    if (!extension.getExternalPoliciesSourceDir().isPresent()) {
                      return false;
                    }
                    File sourceDir = extension.getExternalPoliciesSourceDir().get().getAsFile();
                    return sourceDir.exists() && sourceDir.isDirectory();
                  });
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

              // Configure module path inference for main source compilation and execution tasks.
              // This ensures non-modular dependencies (legacy JARs without module-info.java)
              // are placed on the module path and become "automatic modules" that jGuard
              // can identify and enforce policies on.
              //
              // Tests are explicitly configured to run on the classpath (not module path)
              // because JUnit, AssertJ, and other test frameworks don't have module descriptors.
              project
                  .getTasks()
                  .named(
                      JavaPlugin.COMPILE_JAVA_TASK_NAME,
                      JavaCompile.class,
                      task -> {
                        task.getModularity().getInferModulePath().set(true);
                        // For automatic modules without Automatic-Module-Name manifest attribute,
                        // Gradle's inferModulePath doesn't work. Force module path explicitly.
                        task.doFirst(
                            t -> {
                              JavaCompile jc = (JavaCompile) t;
                              String cp = jc.getClasspath().getAsPath();
                              if (!cp.isEmpty()) {
                                jc.getOptions().getCompilerArgs().add("--module-path");
                                jc.getOptions().getCompilerArgs().add(cp);
                                jc.setClasspath(project.files());
                              }
                            });
                      });

              // Tests run on classpath (not module path) for JUnit/AssertJ compatibility
              project
                  .getTasks()
                  .named(
                      JavaPlugin.COMPILE_TEST_JAVA_TASK_NAME,
                      JavaCompile.class,
                      task -> {
                        task.getModularity().getInferModulePath().set(false);
                      });
              project
                  .getTasks()
                  .withType(
                      Test.class,
                      task -> {
                        task.getModularity().getInferModulePath().set(false);
                      });

              project
                  .getTasks()
                  .withType(
                      JavaExec.class,
                      task -> {
                        // Skip test-related JavaExec tasks
                        if (task.getName().toLowerCase().contains("test")) {
                          return;
                        }
                        task.getModularity().getInferModulePath().set(true);
                        // For automatic modules without Automatic-Module-Name manifest attribute,
                        // Gradle's inferModulePath doesn't work. Force module path explicitly.
                        task.doFirst(
                            t -> {
                              JavaExec je = (JavaExec) t;
                              String cp = je.getClasspath().getAsPath();
                              if (!cp.isEmpty() && je.getMainModule().isPresent()) {
                                je.jvmArgs("--module-path", cp, "-m", je.getMainModule().get());
                                je.setClasspath(project.files());
                              }
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

    // Get external policies task provider lazily
    TaskProvider<CompileExternalPoliciesTask> externalPoliciesTask =
        project.getTasks().named(EXTERNAL_POLICIES_TASK_NAME, CompileExternalPoliciesTask.class);

    project
        .getTasks()
        .register(
            RUN_WITH_AGENT_TASK_NAME,
            JavaExec.class,
            task -> {
              task.setDescription("Run the application with jGuard agent enforcement enabled");
              task.setGroup("application");
              task.dependsOn(compileTask);

              // Also depend on external policies task if source dir is configured
              task.dependsOn(externalPoliciesTask);

              // Wire main class from the run task using providers (lazy)
              task.getMainClass().set(runTaskProvider.flatMap(JavaExec::getMainClass));

              // Auto-detect mainModule from module-info.java if not explicitly set.
              // This enables modular execution so jGuard can properly identify
              // automatic modules (legacy JARs without Automatic-Module-Name).
              task.getMainModule()
                  .set(
                      runTaskProvider.flatMap(
                          run -> {
                            if (run.getMainModule().isPresent()) {
                              return run.getMainModule();
                            }
                            // Auto-detect from module-info.java
                            return project
                                .provider(() -> detectModuleName(project))
                                .orElse(project.provider(() -> null));
                          }));

              // Build classpath: runtime classpath + project JAR (for policy discovery)
              // We get the classpath from the main source set to avoid creating a dependency
              // on the run task, then add the project JAR explicitly for discovery mode.
              JavaPluginExtension javaExt =
                  project.getExtensions().getByType(JavaPluginExtension.class);
              SourceSet mainSourceSet =
                  javaExt.getSourceSets().getByName(SourceSet.MAIN_SOURCE_SET_NAME);

              // Get the jar task to include the project JAR in the classpath
              TaskProvider<Jar> jarTask =
                  project.getTasks().named(JavaPlugin.JAR_TASK_NAME, Jar.class);
              task.dependsOn(jarTask);

              // Combine runtime classpath with project JAR for discovery mode
              task.setClasspath(
                  project
                      .files(jarTask.flatMap(Jar::getArchiveFile))
                      .plus(mainSourceSet.getRuntimeClasspath()));

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

                    // Discovery mode is the default; only explicit false disables it
                    boolean discoveryMode =
                        !Boolean.FALSE.equals(extension.getDiscoveryMode().getOrNull());

                    // Build JVM args
                    List<String> jvmArgs = new ArrayList<>(task.getJvmArgs());

                    if (discoveryMode) {
                      // Discovery mode: no policy path, agent discovers from JARs
                      jvmArgs.add("-javaagent:" + agentJar.getAbsolutePath());

                      // Allow unsigned policies for development
                      if (Boolean.TRUE.equals(extension.getAllowUnsignedPolicies().getOrNull())) {
                        jvmArgs.add("-Djguard.allowUnsignedPolicies=true");
                      }
                    } else {
                      // Single-module mode: pass explicit policy file
                      File policyFile = compileTask.get().getOutputBin().get().getAsFile();
                      if (!policyFile.exists()) {
                        throw new IllegalStateException(
                            "Policy file not found: "
                                + policyFile
                                + ". Run 'compileJGuardPolicy' first.");
                      }
                      jvmArgs.add(
                          "-javaagent:"
                              + agentJar.getAbsolutePath()
                              + "="
                              + policyFile.getAbsolutePath());
                    }

                    // Add external policies directory if configured
                    if (extension.getExternalPoliciesSourceDir().isPresent()) {
                      File sourceDir = extension.getExternalPoliciesSourceDir().get().getAsFile();
                      if (sourceDir.exists() && sourceDir.isDirectory()) {
                        File outputDir = extension.getExternalPoliciesOutputDir().get().getAsFile();
                        jvmArgs.add("-Djguard.policy.override=" + outputDir.getAbsolutePath());
                        project
                            .getLogger()
                            .lifecycle("  External policies: " + outputDir.getAbsolutePath());
                      }
                    }

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

                    // Add hot reload configuration
                    boolean hotReload = Boolean.TRUE.equals(extension.getHotReload().getOrNull());
                    if (hotReload) {
                      jvmArgs.add("-Djguard.reload=true");
                      Integer interval = extension.getHotReloadInterval().getOrNull();
                      if (interval != null && interval != 5) { // Only add if not default
                        jvmArgs.add("-Djguard.reload.interval=" + interval);
                      }
                    }

                    // Add trusted module configuration
                    boolean allowTrusted =
                        Boolean.TRUE.equals(extension.getAllowTrusted().getOrNull());
                    if (allowTrusted) {
                      jvmArgs.add("-Djguard.allow.trusted=true");
                    }

                    task.setJvmArgs(jvmArgs);

                    project.getLogger().lifecycle("Running with jGuard agent...");
                    project.getLogger().lifecycle("  Agent: " + agentJar);
                    if (discoveryMode) {
                      project.getLogger().lifecycle("  Policy: discovery mode (multi-module)");
                    } else {
                      File policyFile = compileTask.get().getOutputBin().get().getAsFile();
                      project.getLogger().lifecycle("  Policy: " + policyFile);
                    }
                    if (mode != null) {
                      project.getLogger().lifecycle("  Mode: " + mode);
                    }
                    if (hotReload) {
                      Integer interval = extension.getHotReloadInterval().getOrNull();
                      project
                          .getLogger()
                          .lifecycle(
                              "  Hot reload: enabled (interval="
                                  + (interval != null ? interval : 5)
                                  + "s)");
                    }
                    if (allowTrusted) {
                      project
                          .getLogger()
                          .warn(
                              "  Trusted modules: ENABLED (security warning: trusted modules bypass all checks)");
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

  /**
   * Auto-detects the module name from module-info.java.
   *
   * @param project the Gradle project
   * @return the module name, or null if not found or not a modular project
   */
  private String detectModuleName(Project project) {
    File moduleInfo = project.file("src/main/java/module-info.java");
    if (!moduleInfo.exists()) {
      return null;
    }

    try {
      String content = new String(java.nio.file.Files.readAllBytes(moduleInfo.toPath()));
      // Simple regex to extract module name from "module foo.bar {"
      java.util.regex.Pattern pattern =
          java.util.regex.Pattern.compile("\\bmodule\\s+([\\w.]+)\\s*\\{");
      java.util.regex.Matcher matcher = pattern.matcher(content);
      if (matcher.find()) {
        return matcher.group(1);
      }
    } catch (Exception e) {
      project.getLogger().debug("Failed to detect module name: {}", e.getMessage());
    }
    return null;
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
    extension.getDiscoveryMode().convention(true); // Auto-discover policies by default
    extension.getAllowUnsignedPolicies().convention(false);

    // External policies defaults
    // Note: externalPoliciesSourceDir has no default - must be explicitly set to enable
    extension
        .getExternalPoliciesOutputDir()
        .convention(project.getLayout().getBuildDirectory().dir("external-policies"));
    extension.getExternalPoliciesIncludeJson().convention(false);

    // Trusted module defaults
    extension.getAllowTrusted().convention(false);

    // Hot reload defaults
    extension.getHotReload().convention(false);
    extension.getHotReloadInterval().convention(5);
  }
}
