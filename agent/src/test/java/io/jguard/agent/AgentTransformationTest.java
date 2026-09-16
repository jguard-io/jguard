/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifies that the agent can actually instrument the JDK types it targets.
 *
 * <p>This forks a JVM with the shaded agent attached, which is the only way to reach the failure it
 * guards against. Resolving an advice class is what triggers the bug, and that only happens during
 * transformation when the agent is running as a real agent; ByteBuddy driven from the ordinary test
 * classpath resolves everything up front and never reproduces it.
 *
 * <p>The bug: {@code Advice.to(SomeAdvice.class)} reflects over the advice class to read its
 * declared methods, which can load classes. Doing that while the JVM is midway through transforming
 * {@code java.lang.ProcessBuilder} raised {@link ClassCircularityError}. The listener logged it and
 * carried on, so the agent reported itself installed while process execution went unguarded - a
 * missing guard rather than a visible failure, which is why it needs a test rather than a log.
 */
class AgentTransformationTest {

  /** Set by the build to the shaded agent JAR; see agent/build.gradle. */
  private static final String AGENT_JAR_PROPERTY = "jguard.agent.jar";

  @Test
  @DisplayName("the agent instruments ProcessBuilder without a transformation error")
  void agent_whenAttached_transformsProcessBuilderWithoutError() throws Exception {
    String agentJar = System.getProperty(AGENT_JAR_PROPERTY);
    assertThat(agentJar)
        .as("the build must pass -D%s pointing at the shaded agent jar", AGENT_JAR_PROPERTY)
        .isNotNull();

    String output = runWithAgent(agentJar);

    assertThat(output)
        .as("the target program must run to completion under the agent")
        .contains("TARGET-DONE");
    assertThat(output)
        .as("no type the agent targets may fail to transform")
        .doesNotContain("Error transforming");
    assertThat(output)
        .as("ProcessBuilder must actually be instrumented, not merely left alone")
        .contains("Transformed: java.lang.ProcessBuilder");
  }

  /** Runs {@link Target} in a new JVM with the agent attached and returns its combined output. */
  private static String runWithAgent(String agentJar) throws IOException, InterruptedException {
    List<String> command = new ArrayList<>();
    command.add(currentJavaBinary());
    command.add("-javaagent:" + agentJar);
    // Discovery mode so the agent needs no policy file, audit mode so nothing is denied: this test
    // is about whether instrumentation installs, not about what the policy allows.
    command.add("-Djguard.discovery=true");
    command.add("-Djguard.mode=AUDIT");
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(Target.class.getName());

    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    String output;
    try (InputStream in = process.getInputStream()) {
      output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    boolean exited = process.waitFor(2, TimeUnit.MINUTES);
    if (!exited) {
      process.destroyForcibly();
      throw new IllegalStateException("target JVM did not exit:\n" + output);
    }
    assertThat(process.exitValue()).as("target JVM output:%n%s", output).isZero();
    return output;
  }

  private static String currentJavaBinary() {
    return ProcessHandle.current()
        .info()
        .command()
        .orElse(System.getProperty("java.home") + "/bin/java");
  }

  /**
   * Touches the instrumented types in a forked JVM.
   *
   * <p>Public with a main method because it is launched as a separate process, not called.
   */
  public static final class Target {

    private Target() {}

    /**
     * Exercises a ProcessBuilder so the agent has to have instrumented it.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
      ProcessBuilder builder = new ProcessBuilder("echo", "jguard");
      System.out.println("TARGET-COMMAND " + builder.command());
      System.out.println("TARGET-DONE");
    }
  }
}
