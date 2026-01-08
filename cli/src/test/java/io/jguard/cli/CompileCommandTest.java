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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/** Tests for the compile subcommand via jguard parent. */
@DisplayName("jguard compile")
class CompileCommandTest {

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
  @DisplayName("compiles valid policy via subcommand")
  void compilesValidPolicy() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path output = tempDir.resolve("policy.bin");

    int exitCode = cmd.execute("compile", "-o", output.toString(), source.toString());

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
  @DisplayName("compiles with JSON output via subcommand")
  void compilesWithJsonOutput() throws IOException, URISyntaxException {
    Path source = getResource("valid-policy.jguard");
    Path binOutput = tempDir.resolve("policy.bin");
    Path jsonOutput = tempDir.resolve("policy.json");

    int exitCode =
        cmd.execute(
            "compile",
            "-o",
            binOutput.toString(),
            "--json",
            jsonOutput.toString(),
            source.toString());

    assertThat(exitCode).isZero();
    assertThat(binOutput).exists();
    assertThat(jsonOutput).exists();

    String json = Files.readString(jsonOutput);
    assertThat(json).contains("\"moduleName\" : \"com.example.app\"");
  }

  @Test
  @DisplayName("fails on missing source file")
  void failsOnMissingSourceFile() {
    Path output = tempDir.resolve("policy.bin");
    Path nonexistent = tempDir.resolve("nonexistent.jguard");

    int exitCode = cmd.execute("compile", "-o", output.toString(), nonexistent.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("does not exist");
  }

  @Test
  @DisplayName("shows compile subcommand help")
  void showsCompileHelp() {
    int exitCode = cmd.execute("compile", "--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("compile");
    assertThat(output).contains("--output");
    assertThat(output).contains("--json");
  }

  @Test
  @DisplayName("shows parent help with available subcommands")
  void showsParentHelp() {
    int exitCode = cmd.execute("--help");

    assertThat(exitCode).isZero();
    String output = out.toString();
    assertThat(output).contains("jguard");
    assertThat(output).contains("compile");
    assertThat(output).contains("inspect");
    assertThat(output).contains("list");
    assertThat(output).contains("diff");
    assertThat(output).contains("validate-override");
  }

  @Test
  @DisplayName("shows version")
  void showsVersion() {
    int exitCode = cmd.execute("--version");

    assertThat(exitCode).isZero();
    assertThat(out.toString()).contains("jguard");
    assertThat(out.toString()).contains("0.2.0");
  }

  // ===== Helper methods =====

  private Path getResource(String name) throws IOException, URISyntaxException {
    var url = getClass().getClassLoader().getResource(name);
    if (url == null) {
      throw new IOException("Resource not found: " + name);
    }
    return Path.of(url.toURI());
  }
}
