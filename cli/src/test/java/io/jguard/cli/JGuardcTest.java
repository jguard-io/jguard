/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/** Tests for the jguardc command-line compiler. */
class JGuardcTest {

  @TempDir Path tempDir;

  private StringWriter out;
  private StringWriter err;
  private CommandLine cmd;

  @BeforeEach
  void setUp() {
    out = new StringWriter();
    err = new StringWriter();
    cmd = new CommandLine(new JGuardc());
    cmd.setOut(new PrintWriter(out));
    cmd.setErr(new PrintWriter(err));
  }

  // ===== Success cases =====

  @Test
  void compilesValidPolicy() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    assertThat(exitCode).isZero();
    assertThat(output).exists();
    assertThat(Files.size(output)).isGreaterThan(0);

    // Verify binary has correct magic header
    byte[] bytes = Files.readAllBytes(output);
    assertThat(bytes[0]).isEqualTo((byte) 'J');
    assertThat(bytes[1]).isEqualTo((byte) 'G');
    assertThat(bytes[2]).isEqualTo((byte) 'R');
    assertThat(bytes[3]).isEqualTo((byte) 'D');
  }

  @Test
  void compilesWithJsonOutput() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path binOutput = tempDir.resolve("policy.bin");
    Path jsonOutput = tempDir.resolve("policy.json");

    int exitCode =
        cmd.execute("-o", binOutput.toString(), "--json", jsonOutput.toString(), source.toString());

    assertThat(exitCode).isZero();
    assertThat(binOutput).exists();
    assertThat(jsonOutput).exists();

    String json = Files.readString(jsonOutput);
    assertThat(json).contains("\"formatVersion\" : 3");
    assertThat(json).contains("\"moduleName\" : \"com.example.app\"");
    assertThat(json).contains("\"capability\" : \"fs.read\"");
  }

  @Test
  void verboseModeShowsProgress() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-v", "-o", output.toString(), source.toString());

    assertThat(exitCode).isZero();
    String errOutput = err.toString();
    assertThat(errOutput).contains("jguardc: compiling");
    assertThat(errOutput).contains("jguardc: wrote");
  }

  @Test
  void createsOutputDirectoryIfNeeded() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output = tempDir.resolve("nested/dir/policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    assertThat(exitCode).isZero();
    assertThat(output).exists();
  }

  // ===== Error cases =====

  @Test
  void failsOnMissingSourceFile() {
    Path output = tempDir.resolve("policy.bin");
    Path nonexistent = tempDir.resolve("nonexistent.jguard");

    int exitCode = cmd.execute("-o", output.toString(), nonexistent.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("does not exist");
  }

  @Test
  void failsOnUnknownCapability() throws IOException, URISyntaxException {
    Path source = getResource("unknown-capability.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    assertThat(exitCode).isEqualTo(1);
    String errOutput = err.toString();
    assertThat(errOutput).contains("error:");
    assertThat(errOutput).contains("Unknown capability");
    assertThat(output).doesNotExist();
  }

  @Test
  void failsOnSyntaxError() throws IOException, URISyntaxException {
    Path source = getResource("syntax-error.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("error:");
    assertThat(output).doesNotExist();
  }

  @Test
  void errorOutputIncludesLineAndColumn() throws IOException, URISyntaxException {
    Path source = getResource("unknown-capability.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    assertThat(exitCode).isEqualTo(1);
    // Format: file:line:column: error: message
    String errOutput = err.toString();
    assertThat(errOutput).matches("(?s).*:\\d+:\\d+: error:.*");
  }

  // ===== Command-line argument handling =====

  @Test
  void showsHelpWithHelpFlag() {
    int exitCode = cmd.execute("--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("jguardc");
    assertThat(output).contains("--output");
    assertThat(output).contains("--json");
    assertThat(output).contains("--verbose");
  }

  @Test
  void showsVersionWithVersionFlag() {
    int exitCode = cmd.execute("--version");

    assertThat(exitCode).isZero();
    assertThat(out.toString()).contains("jguardc");
  }

  @Test
  void failsWhenOutputNotSpecified() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");

    int exitCode = cmd.execute(source.toString());

    assertThat(exitCode).isEqualTo(2); // picocli returns 2 for missing required option
    assertThat(err.toString()).contains("--output");
  }

  @Test
  void failsWhenSourceNotSpecified() {
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString());

    assertThat(exitCode).isEqualTo(2); // picocli returns 2 for missing parameter
  }

  // ===== Warning and strict mode =====

  @Test
  void warningOnRedundantDeny() throws IOException, URISyntaxException {
    Path source = getResource("redundant-deny.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    // Should succeed (exit 0) but produce warning
    assertThat(exitCode).isZero();
    assertThat(output).exists();
    String errOutput = err.toString();
    assertThat(errOutput).contains("warning:");
    assertThat(errOutput).contains("Redundant deny");
  }

  @Test
  void strictModeFailsOnWarning() throws IOException, URISyntaxException {
    Path source = getResource("redundant-deny.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("--strict", "-o", output.toString(), source.toString());

    // Should fail (exit 1) in strict mode
    assertThat(exitCode).isEqualTo(1);
    String errOutput = err.toString();
    assertThat(errOutput).contains("warning:");
    assertThat(errOutput).contains("Redundant deny");
    assertThat(errOutput).contains("--strict mode");
  }

  @Test
  void strictModeSucceedsWithNoWarnings() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("--strict", "-o", output.toString(), source.toString());

    // Should succeed with no warnings
    assertThat(exitCode).isZero();
    assertThat(output).exists();
  }

  @Test
  void defensiveDenyNoWarning() throws IOException, URISyntaxException {
    Path source = getResource("defensive-deny.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("-o", output.toString(), source.toString());

    // Should succeed with no warnings
    assertThat(exitCode).isZero();
    assertThat(output).exists();
    String errOutput = err.toString();
    assertThat(errOutput).doesNotContain("warning:");
    assertThat(errOutput).doesNotContain("Redundant deny");
  }

  @Test
  void strictModeWithDefensiveDenySucceeds() throws IOException, URISyntaxException {
    Path source = getResource("defensive-deny.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("--strict", "-o", output.toString(), source.toString());

    // Should succeed even in strict mode (defensive deny suppresses warning)
    assertThat(exitCode).isZero();
    assertThat(output).exists();
  }

  // ===== Determinism =====

  @Test
  void producesIdenticalOutputForSameInput() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output1 = tempDir.resolve("policy1.bin");
    Path output2 = tempDir.resolve("policy2.bin");

    cmd.execute("-o", output1.toString(), source.toString());

    // Create new command instance
    cmd = new CommandLine(new JGuardc());
    cmd.setOut(new PrintWriter(out));
    cmd.setErr(new PrintWriter(err));

    cmd.execute("-o", output2.toString(), source.toString());

    byte[] bytes1 = Files.readAllBytes(output1);
    byte[] bytes2 = Files.readAllBytes(output2);
    assertThat(bytes1).isEqualTo(bytes2);
  }

  // ===== Helper methods =====

  private Path getResource(String name) throws IOException, URISyntaxException {
    var url = getClass().getClassLoader().getResource(name);
    if (url == null) {
      throw new IOException("Resource not found: " + name);
    }
    // Use toURI() for cross-platform compatibility (getPath() fails on Windows)
    return Path.of(url.toURI());
  }
}
