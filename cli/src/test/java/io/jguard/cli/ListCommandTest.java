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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/** Tests for the list command. */
@DisplayName("jguard list")
class ListCommandTest {

  @TempDir Path tempDir;

  private StringWriter out;
  private StringWriter err;
  private CommandLine cmd;
  private Path libsDir;

  @BeforeEach
  void setUp() throws IOException {
    out = new StringWriter();
    err = new StringWriter();
    cmd = new CommandLine(new JGuard());
    cmd.setOut(new PrintWriter(out));
    cmd.setErr(new PrintWriter(err));
    libsDir = tempDir.resolve("libs");
    Files.createDirectories(libsDir);
  }

  @Test
  @DisplayName("lists policies found in JARs")
  void listsPoliciesInJars() throws IOException {
    createJarWithPolicy(libsDir.resolve("core.jar"), "com.example.core");
    createJarWithPolicy(libsDir.resolve("network.jar"), "com.example.network");

    int exitCode = cmd.execute("list", "--include-unsigned", libsDir.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("Policies found: 2");
    assertThat(output).contains("com.example.core");
    assertThat(output).contains("com.example.network");
  }

  @Test
  @DisplayName("reports empty directory")
  void reportsEmptyDirectory() {
    int exitCode = cmd.execute("list", libsDir.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("Policies found: 0");
    assertThat(output).contains("no policies found");
  }

  @Test
  @DisplayName("skips JARs without policy")
  void skipsJarsWithoutPolicy() throws IOException {
    createJarWithPolicy(libsDir.resolve("with-policy.jar"), "com.example.app");
    createEmptyJar(libsDir.resolve("without-policy.jar"));

    int exitCode = cmd.execute("list", "--include-unsigned", libsDir.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("Policies found: 1");
    assertThat(output).contains("com.example.app");
  }

  @Test
  @DisplayName("verbose mode shows entitlement count")
  void verboseModeShowsEntitlementCount() throws IOException {
    createJarWithPolicy(libsDir.resolve("app.jar"), "com.example.app");

    int exitCode = cmd.execute("list", "--include-unsigned", "-v", libsDir.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("Entitlements:");
  }

  @Test
  @DisplayName("fails on nonexistent directory")
  void failsOnNonexistentDirectory() {
    Path nonexistent = tempDir.resolve("nonexistent");

    int exitCode = cmd.execute("list", nonexistent.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("Not a directory");
  }

  @Test
  @DisplayName("shows help with --help")
  void showsHelp() {
    int exitCode = cmd.execute("list", "--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("list");
    assertThat(output).contains("--include-unsigned");
  }

  // ===== Helper methods =====

  private void createJarWithPolicy(Path jarFile, String moduleName) throws IOException {
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
  }

  private void createEmptyJar(Path jarFile) throws IOException {
    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile.toFile()))) {
      jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      jos.write("Manifest-Version: 1.0\n".getBytes());
      jos.closeEntry();
    }
  }
}
