/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.SubjectPattern;
import io.jguard.policy.serialization.BinaryPolicyWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/** Tests for the inspect command. */
@DisplayName("jguard inspect")
class InspectCommandTest {

  @TempDir Path tempDir;

  private StringWriter out;
  private StringWriter err;
  private CommandLine cmd;

  @BeforeEach
  void setUp() {
    out = new StringWriter();
    err = new StringWriter();
    cmd = new CommandLine(new JGuard());
    cmd.setOut(new PrintWriter(out));
    cmd.setErr(new PrintWriter(err));
  }

  @Test
  @DisplayName("inspects policy file and shows modules")
  void inspectsPolicyFile() throws IOException {
    Path policyFile = createPolicyFile("com.example.app");

    int exitCode = cmd.execute("inspect", policyFile.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("Policy:");
    assertThat(output).contains("Module: com.example.app");
    assertThat(output).contains("Entitlements:");
  }

  @Test
  @DisplayName("inspects JAR with embedded policy")
  void inspectsJarWithPolicy() throws IOException {
    Path jarFile = createJarWithPolicy("com.example.module");

    int exitCode = cmd.execute("inspect", jarFile.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("JAR:");
    assertThat(output).contains("META-INF/jguard/policy.bin");
    assertThat(output).contains("Module: com.example.module");
  }

  @Test
  @DisplayName("reports JAR without embedded policy")
  void reportsJarWithoutPolicy() throws IOException {
    Path jarFile = createEmptyJar();

    int exitCode = cmd.execute("inspect", jarFile.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("No embedded policy found");
  }

  @Test
  @DisplayName("verbose mode shows entitlement details")
  void verboseModeShowsDetails() throws IOException {
    Path policyFile = createPolicyFile("com.example.app");

    int exitCode = cmd.execute("inspect", "-v", policyFile.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("fs.read");
    assertThat(output).contains("/data");
  }

  @Test
  @DisplayName("fails on nonexistent file")
  void failsOnNonexistentFile() {
    Path nonexistent = tempDir.resolve("nonexistent.bin");

    int exitCode = cmd.execute("inspect", nonexistent.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("not found");
  }

  @Test
  @DisplayName("shows help with --help")
  void showsHelp() {
    int exitCode = cmd.execute("inspect", "--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("inspect");
    assertThat(output).contains("JAR");
  }

  // ===== Helper methods =====

  private Path createPolicyFile(String moduleName) throws IOException {
    ModulePolicy module =
        new ModulePolicy(
            moduleName,
            List.of(
                new Entitlement(
                    SubjectPattern.module(),
                    CapabilityGrant.of(
                        "fs.read",
                        List.of(
                            new CapabilityArgument.StringArg("/data"),
                            new CapabilityArgument.StringArg("**"))))));
    ApplicationPolicy policy = ApplicationPolicy.single(module);

    Path policyFile = tempDir.resolve("policy.bin");
    try (FileOutputStream fos = new FileOutputStream(policyFile.toFile())) {
      BinaryPolicyWriter.write(policy, fos);
    }
    return policyFile;
  }

  private Path createJarWithPolicy(String moduleName) throws IOException {
    Path jarFile = tempDir.resolve("module.jar");

    ModulePolicy module =
        new ModulePolicy(
            moduleName,
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ApplicationPolicy policy = ApplicationPolicy.single(module);
    byte[] policyBytes = BinaryPolicyWriter.toBytes(policy);

    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile.toFile()))) {
      jos.putNextEntry(new JarEntry("META-INF/jguard/policy.bin"));
      jos.write(policyBytes);
      jos.closeEntry();
    }

    return jarFile;
  }

  private Path createEmptyJar() throws IOException {
    Path jarFile = tempDir.resolve("empty.jar");

    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile.toFile()))) {
      jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      jos.write("Manifest-Version: 1.0\n".getBytes());
      jos.closeEntry();
    }

    return jarFile;
  }
}
