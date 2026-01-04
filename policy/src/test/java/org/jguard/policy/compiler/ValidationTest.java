/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.compiler;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Tests for policy validation and error reporting. */
class ValidationTest {

  @Test
  void rejectsUnknownCapability() {
    String source =
        """
            security module com.example.app {
                entitle module to unknown.capability;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
    assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Unknown capability"));
  }

  @Test
  void rejectsWrongArgumentCount() {
    String source =
        """
            security module com.example.app {
                entitle module to fs.read("/data");
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
    assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("requires 2 argument"));
  }

  @Test
  void rejectsWrongArgumentType() {
    String source =
        """
            security module com.example.app {
                entitle module to network.listen("not-a-number");
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
    assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("must be integer"));
  }

  @Test
  void rejectsJavaKeywordInModuleName() {
    String source =
        """
            security module com.class.app {
                entitle module to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
    assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Java keyword"));
  }

  @Test
  void rejectsInvalidIdentifierInPackage() {
    String source =
        """
            security module com.example.app {
                entitle 123invalid.pkg to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
  }

  @Test
  void acceptsValidCapabilitiesWithCorrectArgs() {
    String source =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
                entitle module to fs.write("/tmp", "*.log");
                entitle module to network.outbound;
                entitle module to network.listen(8080);
                entitle module to threads.create;
                entitle module to native.load;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.isSuccess()).isTrue();
    assertThat(result.policy().entitlements()).hasSize(6);
  }

  @Test
  void acceptsAllSubjectTypes() {
    String source =
        """
            security module com.example.app {
                entitle module to network.outbound;
                entitle com.example.app.http to network.outbound;
                entitle com.example.app.handlers.* to network.outbound;
                entitle com.example.app.worker.. to threads.create;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.isSuccess()).isTrue();
    assertThat(result.policy().entitlements()).hasSize(4);
  }

  @Test
  void diagnosticsIncludeLineAndColumn() {
    String source =
        """
            security module com.example.app {
                entitle module to bad.capability;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result.hasErrors()).isTrue();
    CompilationResult.Diagnostic diagnostic = result.diagnostics().get(0);
    assertThat(diagnostic.line()).isGreaterThan(0);
    assertThat(diagnostic.column()).isGreaterThan(0);
    assertThat(diagnostic.sourcePath()).isEqualTo("test.jguard");
  }
}
