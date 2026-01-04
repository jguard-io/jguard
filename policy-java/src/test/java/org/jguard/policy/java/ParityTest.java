/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.java;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jguard.policy.java.Capabilities.*;
import static org.jguard.policy.java.Subjects.*;

import java.io.IOException;
import org.jguard.policy.compiler.PolicyCompiler;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.serialization.BinaryPolicyWriter;
import org.jguard.policy.serialization.JsonPolicyWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Parity tests verifying that Java-built policies produce byte-identical output to .jguard files.
 *
 * <p>This is the primary M2 exit criterion: identical input → identical output regardless of
 * whether the policy was defined in Java or in the .jguard DSL.
 */
class ParityTest {

  @Nested
  @DisplayName("Binary Output Parity")
  class BinaryParityTest {

    @Test
    @DisplayName("simple module entitlement produces identical binary")
    void simpleModuleEntitlement() throws IOException {
      // .jguard equivalent
      String jguardSource =
          """
          security module com.example.app {
              entitle module to network.outbound;
          }
          """;

      // Java equivalent
      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app").grant(module(), networkOutbound()).build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("fs.read with arguments produces identical binary")
    void fsReadWithArguments() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle module to fs.read("/data", "*.json");
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), fsRead("/data", "*.json"))
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("exact package subject produces identical binary")
    void exactPackageSubject() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle com.example.app.net to network.outbound;
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(pkg("com.example.app.net"), networkOutbound())
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("direct children subject produces identical binary")
    void directChildrenSubject() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle com.example.handlers.* to network.listen(8080);
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(pkgChildren("com.example.handlers"), networkListen(8080))
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("recursive subject produces identical binary")
    void recursiveSubject() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle com.example.worker.. to threads.create;
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(pkgRecursive("com.example.worker"), threadsCreate())
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("multiple entitlements produce identical binary")
    void multipleEntitlements() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle module to fs.read("/data", "*.json");
              entitle com.example.app.net to network.outbound;
              entitle com.example.app.worker.. to threads.create;
              entitle com.example.app.jni to native.load;
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), fsRead("/data", "*.json"))
              .grant(pkg("com.example.app.net"), networkOutbound())
              .grant(pkgRecursive("com.example.app.worker"), threadsCreate())
              .grant(pkg("com.example.app.jni"), nativeLoad())
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }

    @Test
    @DisplayName("entitlement order does not affect binary output")
    void orderIndependence() throws IOException {
      // Different order in .jguard
      String jguardSource =
          """
          security module com.example.app {
              entitle com.example.app.worker.. to threads.create;
              entitle module to network.outbound;
              entitle com.example.app.net to fs.read("/tmp", "*");
          }
          """;

      // Same entitlements, different order in Java
      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(pkg("com.example.app.net"), fsRead("/tmp", "*"))
              .grant(module(), networkOutbound())
              .grant(pkgRecursive("com.example.app.worker"), threadsCreate())
              .build();

      assertBinaryParity(jguardSource, javaPolicy);
    }
  }

  @Nested
  @DisplayName("JSON Output Parity")
  class JsonParityTest {

    @Test
    @DisplayName("complete policy produces identical JSON")
    void completePolicyJson() throws IOException {
      String jguardSource =
          """
          security module com.example.app {
              entitle module to fs.read("/data", "*.json");
              entitle module to fs.write("/tmp", "*.log");
              entitle com.example.app.net to network.outbound;
              entitle com.example.app.server.* to network.listen(8080);
              entitle com.example.app.worker.. to threads.create;
              entitle com.example.app.jni to native.load;
          }
          """;

      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), fsRead("/data", "*.json"))
              .grant(module(), fsWrite("/tmp", "*.log"))
              .grant(pkg("com.example.app.net"), networkOutbound())
              .grant(pkgChildren("com.example.app.server"), networkListen(8080))
              .grant(pkgRecursive("com.example.app.worker"), threadsCreate())
              .grant(pkg("com.example.app.jni"), nativeLoad())
              .build();

      assertJsonParity(jguardSource, javaPolicy);
    }
  }

  @Nested
  @DisplayName("Deduplication Parity")
  class DeduplicationParityTest {

    @Test
    @DisplayName("duplicate entitlements are deduplicated identically")
    void duplicateEntitlements() throws IOException {
      // .jguard with duplicates
      String jguardSource =
          """
          security module com.example.app {
              entitle module to network.outbound;
              entitle module to network.outbound;
              entitle module to network.outbound;
          }
          """;

      // Java with duplicates
      PolicyDescriptor javaPolicy =
          JGuardPolicy.forModule("com.example.app")
              .grant(module(), networkOutbound())
              .grant(module(), networkOutbound())
              .grant(module(), networkOutbound())
              .build();

      assertBinaryParity(jguardSource, javaPolicy);

      // Also verify deduplication happened
      assertThat(javaPolicy.entitlements()).hasSize(1);
    }
  }

  // ===== Helper Methods =====

  private void assertBinaryParity(String jguardSource, PolicyDescriptor javaPolicy)
      throws IOException {
    PolicyDescriptor jguardPolicy = compileJGuard(jguardSource);

    byte[] jguardBinary = BinaryPolicyWriter.toBytes(jguardPolicy);
    byte[] javaBinary = BinaryPolicyWriter.toBytes(javaPolicy);

    assertThat(javaBinary)
        .as("Java-built policy should produce identical binary to .jguard")
        .isEqualTo(jguardBinary);
  }

  private void assertJsonParity(String jguardSource, PolicyDescriptor javaPolicy)
      throws IOException {
    PolicyDescriptor jguardPolicy = compileJGuard(jguardSource);

    String jguardJson = JsonPolicyWriter.toJson(jguardPolicy);
    String javaJson = JsonPolicyWriter.toJson(javaPolicy);

    assertThat(javaJson)
        .as("Java-built policy should produce identical JSON to .jguard")
        .isEqualTo(jguardJson);
  }

  private PolicyDescriptor compileJGuard(String source) {
    PolicyCompiler.CompileResult result = PolicyCompiler.compileSource(source, "test.jguard");
    assertThat(result.isSuccess()).as("jGuard compilation should succeed").isTrue();
    return result.policy();
  }
}
