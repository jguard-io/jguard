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

/** Tests for the validate-override command. */
@DisplayName("jguard validate-override")
class ValidateOverrideCommandTest {

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
  @DisplayName("passes when override is valid subset")
  void passesWhenOverrideIsValidSubset() throws IOException {
    Path embedded = createPolicy("com.example.app", List.of("fs.read", "threads.create"));
    Path override = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode =
        cmd.execute(
            "validate-override",
            "--embedded",
            embedded.toString(),
            "--override",
            override.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("valid");
  }

  @Test
  @DisplayName("passes when override is identical")
  void passesWhenOverrideIsIdentical() throws IOException {
    Path embedded = createPolicy("com.example.app", List.of("fs.read", "threads.create"));
    Path override = createPolicy("com.example.app", List.of("fs.read", "threads.create"));

    int exitCode =
        cmd.execute(
            "validate-override",
            "--embedded",
            embedded.toString(),
            "--override",
            override.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("valid");
  }

  @Test
  @DisplayName("fails when override contains extra entitlements")
  void failsWhenOverrideContainsExtraEntitlements() throws IOException {
    Path embedded = createPolicy("com.example.app", List.of("fs.read"));
    Path override = createPolicy("com.example.app", List.of("fs.read", "network.outbound"));

    int exitCode =
        cmd.execute(
            "validate-override",
            "--embedded",
            embedded.toString(),
            "--override",
            override.toString());

    assertThat(exitCode).isEqualTo(1);
    String errOutput = err.toString();
    assertThat(errOutput).contains("not in embedded policy");
    assertThat(errOutput).contains("network.outbound");
    assertThat(errOutput).contains("FAILED");
  }

  @Test
  @DisplayName("fails when override references unknown module")
  void failsWhenOverrideReferencesUnknownModule() throws IOException {
    Path embedded = createPolicy("com.example.app", List.of("fs.read"));
    Path override = createPolicy("com.example.other", List.of("fs.read"));

    int exitCode =
        cmd.execute(
            "validate-override",
            "--embedded",
            embedded.toString(),
            "--override",
            override.toString());

    assertThat(exitCode).isEqualTo(1);
    String errOutput = err.toString();
    assertThat(errOutput).contains("unknown module");
    assertThat(errOutput).contains("com.example.other");
  }

  @Test
  @DisplayName("validates override against JAR")
  void validatesOverrideAgainstJar() throws IOException {
    Path jar = createJarWithPolicy("com.example.app", List.of("fs.read", "threads.create"));
    Path override = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode =
        cmd.execute(
            "validate-override", "--jar", jar.toString(), "--override", override.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("valid");
  }

  @Test
  @DisplayName("fails when JAR has no embedded policy")
  void failsWhenJarHasNoEmbeddedPolicy() throws IOException {
    Path jar = createEmptyJar();
    Path override = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode =
        cmd.execute(
            "validate-override", "--jar", jar.toString(), "--override", override.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("No embedded policy");
  }

  @Test
  @DisplayName("fails when neither --jar nor --embedded specified")
  void failsWhenNoEmbeddedSpecified() throws IOException {
    Path override = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode = cmd.execute("validate-override", "--override", override.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("--jar or --embedded");
  }

  @Test
  @DisplayName("fails when both --jar and --embedded specified")
  void failsWhenBothSpecified() throws IOException {
    Path embedded = createPolicy("com.example.app", List.of("fs.read"));
    Path jar = createEmptyJar();
    Path override = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode =
        cmd.execute(
            "validate-override",
            "--jar",
            jar.toString(),
            "--embedded",
            embedded.toString(),
            "--override",
            override.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("Cannot specify both");
  }

  @Test
  @DisplayName("shows help with --help")
  void showsHelp() {
    int exitCode = cmd.execute("validate-override", "--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("validate-override");
    assertThat(output).contains("--embedded");
    assertThat(output).contains("--override");
  }

  // ===== Helper methods =====

  private Path createPolicy(String moduleName, List<String> capabilities) throws IOException {
    List<Entitlement> entitlements =
        capabilities.stream()
            .map(cap -> new Entitlement(SubjectPattern.module(), CapabilityGrant.of(cap)))
            .toList();
    ModulePolicy module = new ModulePolicy(moduleName, entitlements);
    ApplicationPolicy policy = ApplicationPolicy.single(module);

    Path policyFile =
        tempDir.resolve(moduleName.replace(".", "_") + "_" + capabilities.size() + ".bin");
    try (FileOutputStream fos = new FileOutputStream(policyFile.toFile())) {
      BinaryPolicyWriter.write(policy, fos);
    }
    return policyFile;
  }

  private Path createJarWithPolicy(String moduleName, List<String> capabilities)
      throws IOException {
    List<Entitlement> entitlements =
        capabilities.stream()
            .map(cap -> new Entitlement(SubjectPattern.module(), CapabilityGrant.of(cap)))
            .toList();
    ModulePolicy module = new ModulePolicy(moduleName, entitlements);
    ApplicationPolicy policy = ApplicationPolicy.single(module);
    byte[] policyBytes = BinaryPolicyWriter.toBytes(policy);

    Path jarFile = tempDir.resolve("module.jar");
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
