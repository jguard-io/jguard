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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/** Tests for the diff command. */
@DisplayName("jguard diff")
class DiffCommandTest {

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
  @DisplayName("reports identical policies")
  void reportsIdenticalPolicies() throws IOException {
    Path policy1 = createPolicy("com.example.app", List.of("fs.read", "threads.create"));
    Path policy2 = createPolicy("com.example.app", List.of("fs.read", "threads.create"));

    int exitCode = cmd.execute("diff", policy1.toString(), policy2.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("identical");
  }

  @Test
  @DisplayName("shows entitlements only in first file")
  void showsEntitlementsOnlyInFirst() throws IOException {
    Path policy1 = createPolicy("com.example.app", List.of("fs.read", "threads.create"));
    Path policy2 = createPolicy("com.example.app", List.of("fs.read"));

    int exitCode = cmd.execute("diff", policy1.toString(), policy2.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("- ");
    assertThat(output).contains("threads.create");
  }

  @Test
  @DisplayName("shows entitlements only in second file")
  void showsEntitlementsOnlyInSecond() throws IOException {
    Path policy1 = createPolicy("com.example.app", List.of("fs.read"));
    Path policy2 = createPolicy("com.example.app", List.of("fs.read", "network.outbound"));

    int exitCode = cmd.execute("diff", policy1.toString(), policy2.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("+ ");
    assertThat(output).contains("network.outbound");
  }

  @Test
  @DisplayName("shows modules only in one file")
  void showsModulesOnlyInOneFile() throws IOException {
    ModulePolicy module1 =
        new ModulePolicy(
            "com.example.core",
            List.of(new Entitlement(SubjectPattern.module(), CapabilityGrant.of("fs.read"))));
    ModulePolicy module2 =
        new ModulePolicy(
            "com.example.network",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));

    Path policy1 = writePolicyFile("policy1.bin", ApplicationPolicy.single(module1));
    Path policy2 =
        writePolicyFile("policy2.bin", ApplicationPolicy.create(List.of(module1, module2)));

    int exitCode = cmd.execute("diff", policy1.toString(), policy2.toString());

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("only in");
    assertThat(output).contains("com.example.network");
  }

  @Test
  @DisplayName("fails on nonexistent file")
  void failsOnNonexistentFile() throws IOException {
    Path policy1 = createPolicy("com.example.app", List.of("fs.read"));
    Path nonexistent = tempDir.resolve("nonexistent.bin");

    int exitCode = cmd.execute("diff", policy1.toString(), nonexistent.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("not found");
  }

  @Test
  @DisplayName("shows help with --help")
  void showsHelp() {
    int exitCode = cmd.execute("diff", "--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("diff");
    assertThat(output).contains("Compare");
  }

  // ===== Helper methods =====

  private Path createPolicy(String moduleName, List<String> capabilities) throws IOException {
    List<Entitlement> entitlements =
        capabilities.stream()
            .map(cap -> new Entitlement(SubjectPattern.module(), CapabilityGrant.of(cap)))
            .toList();
    ModulePolicy module = new ModulePolicy(moduleName, entitlements);
    ApplicationPolicy policy = ApplicationPolicy.single(module);
    // Use unique filename based on module name, capabilities count, and a counter
    String filename =
        moduleName.replace(".", "_") + "_" + capabilities.size() + "_" + System.nanoTime() + ".bin";
    return writePolicyFile(filename, policy);
  }

  private Path writePolicyFile(String filename, ApplicationPolicy policy) throws IOException {
    Path policyFile = tempDir.resolve(filename);
    try (FileOutputStream fos = new FileOutputStream(policyFile.toFile())) {
      BinaryPolicyWriter.write(policy, fos);
    }
    return policyFile;
  }
}
