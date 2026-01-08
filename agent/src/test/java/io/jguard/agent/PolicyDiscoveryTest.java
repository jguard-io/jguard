/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.SubjectPattern;
import io.jguard.policy.serialization.BinaryPolicyWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for {@link PolicyDiscovery}.
 *
 * <p>Note: These tests use unsigned JARs with allowUnsignedPolicies=true since creating signed JARs
 * in tests is complex. The signature verification logic is tested separately.
 */
@DisplayName("PolicyDiscovery")
class PolicyDiscoveryTest {

  @TempDir Path tempDir;

  @Nested
  @DisplayName("discoverEmbedded()")
  class DiscoverEmbeddedTest {

    @Test
    @DisplayName("discovers policy from unsigned JAR when allowUnsignedPolicies=true")
    void discoversFromUnsignedJarWhenAllowed() throws Exception {
      // Create a JAR with an embedded policy
      Path jarPath = createJarWithPolicy("com.example.app");

      // Set up classpath to include our test JAR
      String originalClasspath = System.getProperty("java.class.path");
      try {
        System.setProperty("java.class.path", jarPath.toString());

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(true)
                .mode(EnforcementMode.STRICT)
                .build();

        ApplicationPolicy policy = PolicyDiscovery.discoverEmbedded(config);

        assertThat(policy.modules()).hasSize(1);
        assertThat(policy.modules().get(0).moduleName()).isEqualTo("com.example.app");
        assertThat(policy.modules().get(0).entitlements()).hasSize(1);
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }

    @Test
    @DisplayName("skips unsigned JARs by default")
    void skipsUnsignedJarsByDefault() throws Exception {
      // Create a JAR with an embedded policy
      Path jarPath = createJarWithPolicy("com.example.app");

      String originalClasspath = System.getProperty("java.class.path");
      try {
        System.setProperty("java.class.path", jarPath.toString());

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(false) // Default - require signatures
                .mode(EnforcementMode.STRICT)
                .build();

        ApplicationPolicy policy = PolicyDiscovery.discoverEmbedded(config);

        // Should be empty since unsigned JARs are skipped
        assertThat(policy.modules()).isEmpty();
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }

    @Test
    @DisplayName("discovers multiple modules from multiple JARs")
    void discoversMultipleModules() throws Exception {
      Path jarA = createJarWithPolicy("com.example.core");
      Path jarB = createJarWithPolicy("com.example.worker");

      String originalClasspath = System.getProperty("java.class.path");
      try {
        System.setProperty("java.class.path", jarA + File.pathSeparator + jarB);

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(true)
                .mode(EnforcementMode.STRICT)
                .build();

        ApplicationPolicy policy = PolicyDiscovery.discoverEmbedded(config);

        assertThat(policy.modules()).hasSize(2);
        assertThat(policy.hasModule("com.example.core")).isTrue();
        assertThat(policy.hasModule("com.example.worker")).isTrue();
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }

    @Test
    @DisplayName("fails fast on duplicate module policies")
    void failsOnDuplicateModules() throws Exception {
      Path jarA = createJarWithPolicy("com.example.app");
      Path jarB = createJarWithPolicy("com.example.app"); // Same module name

      String originalClasspath = System.getProperty("java.class.path");
      try {
        System.setProperty("java.class.path", jarA + File.pathSeparator + jarB);

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(true)
                .mode(EnforcementMode.STRICT)
                .build();

        assertThatThrownBy(() -> PolicyDiscovery.discoverEmbedded(config))
            .isInstanceOf(PolicyDiscovery.PolicyDiscoveryException.class)
            .hasMessageContaining("Duplicate policy")
            .hasMessageContaining("com.example.app");
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }

    @Test
    @DisplayName("loads unnamed module policy from external file")
    void loadsUnnamedModulePolicy() throws Exception {
      // Create an external policy file for unnamed module
      Path unnamedPolicyPath = createPolicyFile(ApplicationPolicy.UNNAMED_MODULE);

      String originalClasspath = System.getProperty("java.class.path");
      try {
        // Clear classpath to simulate no JARs with policies
        System.setProperty("java.class.path", "");

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(true)
                .unnamedModulePolicy(unnamedPolicyPath)
                .mode(EnforcementMode.STRICT)
                .build();

        ApplicationPolicy policy = PolicyDiscovery.discoverEmbedded(config);

        assertThat(policy.modules()).hasSize(1);
        assertThat(policy.hasModule(ApplicationPolicy.UNNAMED_MODULE)).isTrue();
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }

    @Test
    @DisplayName("returns empty policy when no JARs have embedded policies")
    void returnsEmptyPolicyWhenNoEmbeddedPolicies() throws Exception {
      // Create a JAR without an embedded policy
      Path jarPath = createJarWithoutPolicy();

      String originalClasspath = System.getProperty("java.class.path");
      try {
        System.setProperty("java.class.path", jarPath.toString());

        AgentConfig config =
            new AgentConfig.Builder()
                .discoveryEnabled(true)
                .allowUnsignedPolicies(true)
                .mode(EnforcementMode.STRICT)
                .build();

        ApplicationPolicy policy = PolicyDiscovery.discoverEmbedded(config);

        assertThat(policy.modules()).isEmpty();
      } finally {
        System.setProperty("java.class.path", originalClasspath);
      }
    }
  }

  @Nested
  @DisplayName("JarSignatureVerifier")
  class JarSignatureVerifierTest {

    @Test
    @DisplayName("hasEmbeddedPolicy returns true for JAR with policy")
    void hasEmbeddedPolicyReturnsTrue() throws Exception {
      Path jarPath = createJarWithPolicy("com.example.app");

      try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarPath.toFile())) {
        assertThat(JarSignatureVerifier.hasEmbeddedPolicy(jarFile)).isTrue();
      }
    }

    @Test
    @DisplayName("hasEmbeddedPolicy returns false for JAR without policy")
    void hasEmbeddedPolicyReturnsFalse() throws Exception {
      Path jarPath = createJarWithoutPolicy();

      try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarPath.toFile())) {
        assertThat(JarSignatureVerifier.hasEmbeddedPolicy(jarFile)).isFalse();
      }
    }

    @Test
    @DisplayName("isSignedAndValid returns false for unsigned JAR")
    void isSignedAndValidReturnsFalseForUnsigned() throws Exception {
      Path jarPath = createJarWithPolicy("com.example.app");

      try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarPath.toFile())) {
        assertThat(JarSignatureVerifier.isSignedAndValid(jarFile)).isFalse();
      }
    }

    @Test
    @DisplayName("getSignerInfo returns 'unsigned' for unsigned JAR")
    void getSignerInfoReturnsUnsigned() throws Exception {
      Path jarPath = createJarWithPolicy("com.example.app");

      try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(jarPath.toFile())) {
        assertThat(JarSignatureVerifier.getSignerInfo(jarFile)).isEqualTo("unsigned");
      }
    }
  }

  // ===== Helper methods =====

  private Path createJarWithPolicy(String moduleName) throws Exception {
    Path jarPath = tempDir.resolve(moduleName.replace('.', '-') + ".jar");

    // Create the policy
    ModulePolicy modulePolicy =
        new ModulePolicy(
            moduleName,
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ApplicationPolicy appPolicy = ApplicationPolicy.single(modulePolicy);
    byte[] policyBytes = BinaryPolicyWriter.toBytes(appPolicy);

    // Create the JAR
    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
      // Add the policy entry
      jos.putNextEntry(new JarEntry(JarSignatureVerifier.POLICY_LOCATION));
      jos.write(policyBytes);
      jos.closeEntry();
    }

    return jarPath;
  }

  private Path createJarWithoutPolicy() throws Exception {
    Path jarPath = tempDir.resolve("no-policy.jar");

    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
      // Add a dummy entry
      jos.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      jos.write("Manifest-Version: 1.0\n".getBytes());
      jos.closeEntry();
    }

    return jarPath;
  }

  private Path createPolicyFile(String moduleName) throws Exception {
    Path policyPath = tempDir.resolve(moduleName + ".bin");

    ModulePolicy modulePolicy =
        new ModulePolicy(
            moduleName,
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ApplicationPolicy appPolicy = ApplicationPolicy.single(modulePolicy);
    byte[] policyBytes = BinaryPolicyWriter.toBytes(appPolicy);

    Files.write(policyPath, policyBytes);
    return policyPath;
  }

  @BeforeEach
  void setUp() {
    // Ensure we start with a clean slate
  }
}
