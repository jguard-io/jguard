/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.jguard.bootstrap.AgentConfig;
import org.jguard.bootstrap.EnforcementMode;
import org.jguard.policy.model.CapabilityGrant;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;
import org.jguard.policy.serialization.BinaryPolicyWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests for {@link PolicyReloader}. */
class PolicyReloaderTest {

  @TempDir Path tempDir;

  private Path policyPath;
  private AtomicReference<PolicyEnforcer> enforcerRef;
  private PolicyReloader reloader;
  private AgentConfig config;

  @BeforeEach
  void setUp() throws IOException {
    policyPath = tempDir.resolve("policy.bin");

    // Create initial policy
    PolicyDescriptor initialPolicy = createPolicy("com.example.app", "network.outbound");
    writePolicyFile(policyPath, initialPolicy);

    // Create config
    config = new AgentConfig.Builder().policyPath(policyPath).mode(EnforcementMode.STRICT).build();

    // Create initial enforcer
    PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialPolicy, config);
    enforcerRef = new AtomicReference<>(initialEnforcer);
  }

  @AfterEach
  void tearDown() {
    if (reloader != null && reloader.isRunning()) {
      reloader.stop();
    }
  }

  @Test
  @DisplayName("starts and stops without error")
  void startsAndStops() {
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);

    reloader.start();
    assertThat(reloader.isRunning()).isTrue();

    reloader.stop();
    assertThat(reloader.isRunning()).isFalse();
  }

  @Test
  @DisplayName("does not restart if already running")
  void doesNotRestartIfRunning() {
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);

    reloader.start();
    assertThat(reloader.isRunning()).isTrue();

    // Calling start again should be a no-op
    reloader.start();
    assertThat(reloader.isRunning()).isTrue();
  }

  @Test
  @DisplayName("reloads policy when file changes")
  void reloadsPolicyWhenFileChanges() throws Exception {
    // Use 1 second poll interval for test speed
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
    reloader.start();

    // Get initial enforcer reference
    PolicyEnforcer initialEnforcer = enforcerRef.get();
    assertThat(initialEnforcer).isNotNull();

    // Wait a moment to ensure we're past initial file check
    Thread.sleep(100);

    // Update the policy file
    PolicyDescriptor newPolicy =
        createPolicy("com.example.app", "network.outbound", "threads.create");
    writePolicyFile(policyPath, newPolicy);

    // Wait for reload (poll interval + some buffer)
    Thread.sleep(2000);

    // Verify enforcer was swapped
    PolicyEnforcer newEnforcer = enforcerRef.get();
    assertThat(newEnforcer).isNotNull();
    assertThat(newEnforcer).isNotSameAs(initialEnforcer);
  }

  @Test
  @DisplayName("does not reload if file unchanged")
  void doesNotReloadIfUnchanged() throws Exception {
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
    reloader.start();

    // Get initial enforcer
    PolicyEnforcer initialEnforcer = enforcerRef.get();

    // Wait for a few poll cycles
    Thread.sleep(3000);

    // Enforcer should be the same instance
    assertThat(enforcerRef.get()).isSameAs(initialEnforcer);
  }

  @Test
  @DisplayName("handles missing policy file gracefully")
  void handlesMissingPolicyFile() throws Exception {
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
    reloader.start();

    PolicyEnforcer initialEnforcer = enforcerRef.get();

    // Delete the policy file
    Files.delete(policyPath);

    // Wait for poll cycle
    Thread.sleep(2000);

    // Enforcer should remain unchanged
    assertThat(enforcerRef.get()).isSameAs(initialEnforcer);
    assertThat(reloader.isRunning()).isTrue();
  }

  @Test
  @DisplayName("handles corrupted policy file gracefully")
  void handlesCorruptedPolicyFile() throws Exception {
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
    reloader.start();

    PolicyEnforcer initialEnforcer = enforcerRef.get();

    // Wait a moment
    Thread.sleep(100);

    // Write garbage to the policy file
    Files.writeString(policyPath, "not a valid policy file");

    // Wait for poll cycle
    Thread.sleep(2000);

    // Enforcer should remain unchanged (reload failed)
    assertThat(enforcerRef.get()).isSameAs(initialEnforcer);
    assertThat(reloader.isRunning()).isTrue();
  }

  @Test
  @DisplayName("uses configured poll interval")
  void usesConfiguredPollInterval() throws Exception {
    // Use 2 second poll interval
    reloader = new PolicyReloader(policyPath, enforcerRef, config, 2);
    reloader.start();

    PolicyEnforcer initialEnforcer = enforcerRef.get();

    // Update file immediately
    PolicyDescriptor newPolicy = createPolicy("com.example.app", "threads.create");
    writePolicyFile(policyPath, newPolicy);

    // Wait 500ms - well below poll interval
    Thread.sleep(500);

    // Should not have reloaded yet
    assertThat(enforcerRef.get()).isSameAs(initialEnforcer);

    // Wait for poll time + generous buffer for slow CI machines
    Thread.sleep(4000);

    // Now should have reloaded
    assertThat(enforcerRef.get()).isNotSameAs(initialEnforcer);
  }

  // ===== Helper methods =====

  private PolicyDescriptor createPolicy(String moduleName, String... capabilities) {
    List<Entitlement> entitlements =
        java.util.Arrays.stream(capabilities)
            .map(cap -> new Entitlement(SubjectPattern.module(), CapabilityGrant.of(cap)))
            .toList();
    return PolicyDescriptor.create(moduleName, entitlements);
  }

  private void writePolicyFile(Path path, PolicyDescriptor policy) throws IOException {
    try (OutputStream out = Files.newOutputStream(path)) {
      BinaryPolicyWriter.write(policy, out);
    }
  }
}
