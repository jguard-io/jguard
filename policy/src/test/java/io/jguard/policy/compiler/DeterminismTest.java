/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.compiler;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.policy.serialization.BinaryPolicyWriter;
import io.jguard.policy.serialization.JsonPolicyWriter;
import java.io.IOException;
import org.junit.jupiter.api.Test;

/**
 * Tests that the policy compiler produces deterministic output.
 *
 * <p>Identical source files must produce byte-identical compiled output. Semantically equivalent
 * sources (e.g., different entitlement ordering) must also produce identical output after
 * normalization.
 */
class DeterminismTest {

  @Test
  void sameSourceProducesIdenticalBinaryOutput() throws IOException {
    String source =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
                entitle com.example.app.http to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result1 = PolicyCompiler.compileSource(source, "test.jguard");
    PolicyCompiler.CompileResult result2 = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result1.isSuccess()).isTrue();
    assertThat(result2.isSuccess()).isTrue();

    byte[] binary1 = BinaryPolicyWriter.toBytes(result1.policy());
    byte[] binary2 = BinaryPolicyWriter.toBytes(result2.policy());

    assertThat(binary1).isEqualTo(binary2);
  }

  @Test
  void sameSourceProducesIdenticalJsonOutput() throws IOException {
    String source =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
                entitle com.example.app.http to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result1 = PolicyCompiler.compileSource(source, "test.jguard");
    PolicyCompiler.CompileResult result2 = PolicyCompiler.compileSource(source, "test.jguard");

    assertThat(result1.isSuccess()).isTrue();
    assertThat(result2.isSuccess()).isTrue();

    String json1 = JsonPolicyWriter.toJson(result1.policy());
    String json2 = JsonPolicyWriter.toJson(result2.policy());

    assertThat(json1).isEqualTo(json2);
  }

  @Test
  void differentEntitlementOrderingProducesIdenticalOutput() throws IOException {
    // Same entitlements in different order
    String source1 =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
                entitle com.example.app.http to network.outbound;
                entitle com.example.app.worker.. to threads.create;
            }
            """;

    String source2 =
        """
            security module com.example.app {
                entitle com.example.app.worker.. to threads.create;
                entitle module to fs.read("/data", "*.json");
                entitle com.example.app.http to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result1 = PolicyCompiler.compileSource(source1, "test1.jguard");
    PolicyCompiler.CompileResult result2 = PolicyCompiler.compileSource(source2, "test2.jguard");

    assertThat(result1.isSuccess()).isTrue();
    assertThat(result2.isSuccess()).isTrue();

    // Binary output should be identical after normalization
    byte[] binary1 = BinaryPolicyWriter.toBytes(result1.policy());
    byte[] binary2 = BinaryPolicyWriter.toBytes(result2.policy());

    assertThat(binary1).isEqualTo(binary2);

    // JSON output should be identical after normalization
    String json1 = JsonPolicyWriter.toJson(result1.policy());
    String json2 = JsonPolicyWriter.toJson(result2.policy());

    assertThat(json1).isEqualTo(json2);
  }

  @Test
  void duplicateEntitlementsAreDeduplicatedDeterministically() throws IOException {
    // Duplicate entitlements should be deduplicated
    String source1 =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
                entitle module to fs.read("/data", "*.json");
            }
            """;

    String source2 =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
            }
            """;

    PolicyCompiler.CompileResult result1 = PolicyCompiler.compileSource(source1, "test1.jguard");
    PolicyCompiler.CompileResult result2 = PolicyCompiler.compileSource(source2, "test2.jguard");

    assertThat(result1.isSuccess()).isTrue();
    assertThat(result2.isSuccess()).isTrue();

    // After deduplication, output should be identical
    byte[] binary1 = BinaryPolicyWriter.toBytes(result1.policy());
    byte[] binary2 = BinaryPolicyWriter.toBytes(result2.policy());

    assertThat(binary1).isEqualTo(binary2);
  }

  @Test
  void binaryOutputHasCorrectMagicHeader() throws IOException {
    String source =
        """
            security module com.example.app {
                entitle module to network.outbound;
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");
    assertThat(result.isSuccess()).isTrue();

    byte[] binary = BinaryPolicyWriter.toBytes(result.policy());

    // Magic header: "JGRD"
    assertThat(binary[0]).isEqualTo((byte) 'J');
    assertThat(binary[1]).isEqualTo((byte) 'G');
    assertThat(binary[2]).isEqualTo((byte) 'R');
    assertThat(binary[3]).isEqualTo((byte) 'D');

    // Version: 1
    assertThat(binary[4]).isEqualTo((byte) 1);
  }

  @Test
  void jsonOutputHasExpectedStructure() throws IOException {
    String source =
        """
            security module com.example.app {
                entitle module to fs.read("/data", "*.json");
            }
            """;

    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");
    assertThat(result.isSuccess()).isTrue();

    String json = JsonPolicyWriter.toJson(result.policy());

    assertThat(json).contains("\"formatVersion\" : 3");
    assertThat(json).contains("\"moduleName\" : \"com.example.app\"");
    assertThat(json).contains("\"entitlements\"");
    assertThat(json).contains("\"capability\" : \"fs.read\"");
  }
}
