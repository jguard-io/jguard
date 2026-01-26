/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.CallerContext;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.bootstrap.Operation;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Denial;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.SubjectPattern;
import io.jguard.policy.serialization.BinaryPolicyWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Integration tests for multi-module policy hot reload.
 *
 * <p>Tests scenarios where:
 *
 * <ul>
 *   <li>Multiple modules have separate policies
 *   <li>External policy directory contains policies for multiple modules
 *   <li>Global policy affects all modules
 *   <li>Changes to one module's policy don't affect other modules
 * </ul>
 */
@DisplayName("Multi-Module Hot Reload")
class MultiModuleHotReloadTest {

  @TempDir Path tempDir;

  private Path policyPath;
  private Path overrideDir;
  private AtomicReference<PolicyEnforcer> enforcerRef;
  private PolicyReloader reloader;
  private AgentConfig config;

  @BeforeEach
  void setUp() throws IOException {
    policyPath = tempDir.resolve("policy.bin");
    overrideDir = tempDir.resolve("overrides");
    Files.createDirectories(overrideDir);
  }

  @AfterEach
  void tearDown() {
    if (reloader != null && reloader.isRunning()) {
      reloader.stop();
    }
  }

  @Nested
  @DisplayName("Multi-module policy file")
  class MultiModulePolicyFile {

    @Test
    @DisplayName("reloads policy with multiple modules")
    void reloadsMultiModulePolicy() throws Exception {
      // Create initial policy with two modules
      ApplicationPolicy initialPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read"),
              createModule("com.example.network", "network.outbound"));
      writePolicyFile(policyPath, initialPolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, null);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      // Verify initial state
      assertModuleHasCapability("com.example.core", "fs.read");
      assertModuleDoesNotHaveCapability("com.example.core", "threads.create");
      assertModuleHasCapability("com.example.network", "network.outbound");

      Thread.sleep(100);

      // Update policy: add capability to core, remove from network
      ApplicationPolicy newPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read", "threads.create"),
              createModule("com.example.network")); // network.outbound removed
      writePolicyFile(policyPath, newPolicy);

      // Wait for reload
      Thread.sleep(2000);

      // Verify new state
      PolicyEnforcer newEnforcer = enforcerRef.get();
      assertThat(newEnforcer).isNotSameAs(initialEnforcer);
      assertModuleHasCapability("com.example.core", "fs.read");
      assertModuleHasCapability("com.example.core", "threads.create");
      assertModuleDoesNotHaveCapability("com.example.network", "network.outbound");
    }

    @Test
    @DisplayName("adding new module during reload")
    void addingNewModuleDuringReload() throws Exception {
      // Initial: single module
      ApplicationPolicy initialPolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read"));
      writePolicyFile(policyPath, initialPolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, null);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      assertThat(enforcerRef.get().getModuleNames()).containsExactly("com.example.core");

      Thread.sleep(100);

      // Add a new module
      ApplicationPolicy newPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read"),
              createModule("com.example.network", "network.outbound"));
      writePolicyFile(policyPath, newPolicy);

      Thread.sleep(2000);

      // Verify both modules exist
      assertThat(enforcerRef.get().getModuleNames())
          .containsExactlyInAnyOrder("com.example.core", "com.example.network");
      assertModuleHasCapability("com.example.network", "network.outbound");
    }

    @Test
    @DisplayName("removing module during reload")
    void removingModuleDuringReload() throws Exception {
      // Initial: two modules
      ApplicationPolicy initialPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read"),
              createModule("com.example.network", "network.outbound"));
      writePolicyFile(policyPath, initialPolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, null);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      assertThat(enforcerRef.get().getModuleNames()).hasSize(2);

      Thread.sleep(100);

      // Remove network module
      ApplicationPolicy newPolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read"));
      writePolicyFile(policyPath, newPolicy);

      Thread.sleep(2000);

      // Verify only core remains
      assertThat(enforcerRef.get().getModuleNames()).containsExactly("com.example.core");
    }
  }

  @Nested
  @DisplayName("External policy directory hot reload")
  class ExternalPolicyDirectoryReload {

    @Test
    @DisplayName("reloads when external policy file changes")
    void reloadsOnExternalPolicyChange() throws Exception {
      // Base policy with core module
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read", "network.outbound"));
      writePolicyFile(policyPath, basePolicy);
      backdateFile(policyPath);

      // External policy: deny network.outbound for core
      ModulePolicy coreDeny =
          new ModulePolicy(
              "com.example.core",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.core.bin", coreDeny);
      backdateFile(overrideDir.resolve("com.example.core.bin"));

      config = createConfig(policyPath, overrideDir);
      ApplicationPolicy mergedPolicy = PolicyMerger.merge(basePolicy, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(mergedPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      // Verify initial: network.outbound denied
      assertModuleDoesNotHaveCapability("com.example.core", "network.outbound");
      assertModuleHasCapability("com.example.core", "fs.read");

      Thread.sleep(100);

      // Update external policy: remove the denial
      ModulePolicy coreGrant =
          new ModulePolicy(
              "com.example.core",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("com.example.core.bin", coreGrant);

      Thread.sleep(2000);

      // Verify: network.outbound restored (no more denial), threads.create added
      assertModuleHasCapability("com.example.core", "network.outbound");
      assertModuleHasCapability("com.example.core", "threads.create");
    }

    @Test
    @DisplayName("adding external policy for new module")
    void addingExternalPolicyForNewModule() throws Exception {
      // Base policy with core module only
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read"));
      writePolicyFile(policyPath, basePolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(basePolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      assertThat(enforcerRef.get().getModuleNames()).containsExactly("com.example.core");

      Thread.sleep(100);

      // Add external policy for a legacy library (new module)
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      Thread.sleep(2000);

      // Verify legacy module was added
      assertThat(enforcerRef.get().getModuleNames())
          .containsExactlyInAnyOrder("com.example.core", "legacy.library");
      assertModuleHasCapability("legacy.library", "threads.create");
    }

    @Test
    @DisplayName("global policy changes affect all modules")
    void globalPolicyChangesAffectAllModules() throws Exception {
      // Base policy with two modules
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read", "network.outbound"),
              createModule("com.example.network", "network.outbound", "threads.create"));
      writePolicyFile(policyPath, basePolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(basePolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      // Verify initial: both have network.outbound
      assertModuleHasCapability("com.example.core", "network.outbound");
      assertModuleHasCapability("com.example.network", "network.outbound");

      Thread.sleep(100);

      // Add global policy denying network.outbound for all modules
      ModulePolicy globalDeny =
          new ModulePolicy(
              "_global",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("_global.bin", globalDeny);

      Thread.sleep(2000);

      // Verify: network.outbound denied for BOTH modules
      assertModuleDoesNotHaveCapability("com.example.core", "network.outbound");
      assertModuleDoesNotHaveCapability("com.example.network", "network.outbound");
      // Other capabilities unchanged
      assertModuleHasCapability("com.example.core", "fs.read");
      assertModuleHasCapability("com.example.network", "threads.create");
    }

    @Test
    @DisplayName("removing external policy file restores embedded policy")
    void removingExternalPolicyRestoresEmbedded() throws Exception {
      // Base policy with core module having network.outbound
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read", "network.outbound"));
      writePolicyFile(policyPath, basePolicy);
      backdateFile(policyPath);

      // External policy: deny network.outbound
      Path externalPath = overrideDir.resolve("com.example.core.bin");
      ModulePolicy coreDeny =
          new ModulePolicy(
              "com.example.core",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.core.bin", coreDeny);
      backdateFile(externalPath);

      config = createConfig(policyPath, overrideDir);
      ApplicationPolicy mergedPolicy = PolicyMerger.merge(basePolicy, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(mergedPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      // Verify initial: network.outbound denied
      assertModuleDoesNotHaveCapability("com.example.core", "network.outbound");

      Thread.sleep(100);

      // Delete the external policy file
      Files.delete(externalPath);
      // Touch the directory to trigger reload check
      Files.setLastModifiedTime(overrideDir, FileTime.fromMillis(System.currentTimeMillis()));

      Thread.sleep(2000);

      // Verify: network.outbound restored from embedded
      assertModuleHasCapability("com.example.core", "network.outbound");
    }
  }

  @Nested
  @DisplayName("Discovery mode with external policies")
  class DiscoveryModeReload {

    @Test
    @DisplayName("hot reload in discovery mode watches only override directory")
    void discoveryModeWatchesOnlyOverrideDir() throws Exception {
      // Simulate discovered base policy (from JARs)
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read", "network.outbound"));

      config = createConfig(null, overrideDir);
      ApplicationPolicy initialMerged = PolicyMerger.merge(basePolicy, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialMerged, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      // Use discovery mode (base policy cached)
      reloader = PolicyReloader.forDiscoveryMode(basePolicy, enforcerRef, config, 1);
      reloader.start();

      assertThat(reloader.isDiscoveryMode()).isTrue();
      assertModuleHasCapability("com.example.core", "network.outbound");

      Thread.sleep(100);

      // Add external policy with denial
      ModulePolicy coreDeny =
          new ModulePolicy(
              "com.example.core",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.core.bin", coreDeny);

      Thread.sleep(2000);

      // Verify: denial applied
      assertModuleDoesNotHaveCapability("com.example.core", "network.outbound");
      assertModuleHasCapability("com.example.core", "fs.read");
    }

    @Test
    @DisplayName("discovery mode adds legacy modules from external policies")
    void discoveryModeAddsLegacyModules() throws Exception {
      // Simulate discovered base policy
      ApplicationPolicy basePolicy =
          createMultiModulePolicy(createModule("com.example.core", "fs.read"));

      config = createConfig(null, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(basePolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = PolicyReloader.forDiscoveryMode(basePolicy, enforcerRef, config, 1);
      reloader.start();

      assertThat(enforcerRef.get().getModuleNames()).containsExactly("com.example.core");

      Thread.sleep(100);

      // Add external policy for legacy library (use createCapability for proper fs.read args)
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), createCapability("fs.read")),
                  new Entitlement(SubjectPattern.module(), createCapability("threads.create"))),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      Thread.sleep(2000);

      // Verify legacy module added
      assertThat(enforcerRef.get().getModuleNames())
          .containsExactlyInAnyOrder("com.example.core", "legacy.library");
      assertModuleHasCapability("legacy.library", "fs.read");
      assertModuleHasCapability("legacy.library", "threads.create");
    }
  }

  @Nested
  @DisplayName("Module isolation during reload")
  class ModuleIsolation {

    @Test
    @DisplayName("changes to one module don't affect other modules")
    void changesIsolatedPerModule() throws Exception {
      ApplicationPolicy initialPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read", "network.outbound"),
              createModule("com.example.network", "network.outbound", "threads.create"));
      writePolicyFile(policyPath, initialPolicy);
      backdateFile(policyPath);

      config = createConfig(policyPath, overrideDir);
      PolicyEnforcer initialEnforcer = new PolicyEnforcer(initialPolicy, config);
      enforcerRef = new AtomicReference<>(initialEnforcer);

      reloader = new PolicyReloader(policyPath, enforcerRef, config, 1);
      reloader.start();

      // Verify initial state for both modules
      assertModuleHasCapability("com.example.core", "fs.read");
      assertModuleHasCapability("com.example.core", "network.outbound");
      assertModuleHasCapability("com.example.network", "network.outbound");
      assertModuleHasCapability("com.example.network", "threads.create");

      Thread.sleep(100);

      // Update only core module (remove network.outbound)
      ApplicationPolicy newPolicy =
          createMultiModulePolicy(
              createModule("com.example.core", "fs.read"), // network.outbound removed
              createModule(
                  "com.example.network", "network.outbound", "threads.create")); // unchanged
      writePolicyFile(policyPath, newPolicy);

      Thread.sleep(2000);

      // Core module changed
      assertModuleHasCapability("com.example.core", "fs.read");
      assertModuleDoesNotHaveCapability("com.example.core", "network.outbound");

      // Network module unchanged
      assertModuleHasCapability("com.example.network", "network.outbound");
      assertModuleHasCapability("com.example.network", "threads.create");
    }
  }

  // ===== Helper methods =====

  private ModulePolicy createModule(String name, String... capabilities) {
    List<Entitlement> entitlements =
        java.util.Arrays.stream(capabilities)
            .map(cap -> new Entitlement(SubjectPattern.module(), createCapability(cap)))
            .toList();
    return new ModulePolicy(name, entitlements, List.of());
  }

  private CapabilityGrant createCapability(String cap) {
    // fs.read and fs.write need root + glob arguments
    // Use system temp dir for cross-platform compatibility
    if (cap.equals("fs.read") || cap.equals("fs.write")) {
      String tempRoot = System.getProperty("java.io.tmpdir");
      return CapabilityGrant.of(
          cap,
          List.of(
              new io.jguard.policy.model.CapabilityArgument.StringArg(tempRoot),
              new io.jguard.policy.model.CapabilityArgument.StringArg("**")));
    }
    return CapabilityGrant.of(cap);
  }

  private ApplicationPolicy createMultiModulePolicy(ModulePolicy... modules) {
    return ApplicationPolicy.create(List.of(modules));
  }

  private void writePolicyFile(Path path, ApplicationPolicy policy) throws IOException {
    try (OutputStream out = Files.newOutputStream(path)) {
      BinaryPolicyWriter.write(policy, out);
    }
  }

  private void writeExternalPolicy(String filename, ModulePolicy policy) throws IOException {
    Path policyPath = overrideDir.resolve(filename);
    ApplicationPolicy appPolicy = ApplicationPolicy.single(policy);
    try (FileOutputStream fos = new FileOutputStream(policyPath.toFile())) {
      BinaryPolicyWriter.write(appPolicy, fos);
    }
  }

  private void backdateFile(Path path) throws IOException {
    Files.setLastModifiedTime(path, FileTime.fromMillis(System.currentTimeMillis() - 2000));
  }

  private AgentConfig createConfig(Path policyPath, Path overrideDir) {
    AgentConfig.Builder builder = new AgentConfig.Builder().mode(EnforcementMode.STRICT);
    if (policyPath != null) {
      builder.policyPath(policyPath);
    } else {
      // For discovery mode, enable discovery
      builder.discoveryEnabled(true);
    }
    if (overrideDir != null) {
      builder.overrideDir(overrideDir);
    }
    return builder.build();
  }

  private void assertModuleHasCapability(String moduleName, String capability) {
    PolicyEnforcer enforcer = enforcerRef.get();
    CallerContext caller = new CallerContext(moduleName + ".test", moduleName);

    Operation op = getOperationForCapability(capability);
    if (op == null) {
      throw new IllegalArgumentException("Unknown capability: " + capability);
    }

    SecurityException result = checkOperation(enforcer, caller, op);
    assertThat(result).as("Module %s should have capability %s", moduleName, capability).isNull();
  }

  private void assertModuleDoesNotHaveCapability(String moduleName, String capability) {
    PolicyEnforcer enforcer = enforcerRef.get();
    CallerContext caller = new CallerContext(moduleName + ".test", moduleName);

    Operation op = getOperationForCapability(capability);
    if (op == null) {
      throw new IllegalArgumentException("Unknown capability: " + capability);
    }

    SecurityException result = checkOperation(enforcer, caller, op);
    assertThat(result)
        .as("Module %s should NOT have capability %s", moduleName, capability)
        .isNotNull();
  }

  private Operation getOperationForCapability(String capability) {
    return switch (capability) {
      case "fs.read" -> Operation.FS_READ;
      case "fs.write" -> Operation.FS_WRITE;
      case "network.outbound" -> Operation.NET_CONNECT;
      case "network.listen" -> Operation.NET_LISTEN;
      case "threads.create" -> Operation.THREAD_CREATE;
      case "native.load" -> Operation.NATIVE_LOAD;
      case "env.read" -> Operation.ENV_READ;
      case "system.property.read" -> Operation.PROP_READ;
      case "system.property.write" -> Operation.PROP_WRITE;
      default -> null;
    };
  }

  private SecurityException checkOperation(
      PolicyEnforcer enforcer, CallerContext caller, Operation op) {
    // Use system temp dir for fs.read/fs.write to match the capability grants
    Path testFile = java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"), "test.txt");
    return switch (op) {
      case FS_READ -> enforcer.check(caller, op, testFile, 0);
      case FS_WRITE -> enforcer.check(caller, op, testFile, 0);
      case FS_HARDLINK -> enforcer.check(caller, op, testFile, 0);
      case NET_CONNECT -> enforcer.check(caller, op, "example.com", 80);
      case NET_LISTEN -> enforcer.check(caller, op, 8080, 0);
      case THREAD_CREATE,
          NATIVE_LOAD,
          ENV_READ,
          PROP_READ,
          PROP_WRITE,
          PROCESS_EXEC,
          CRYPTO_PROVIDER,
          RUNTIME_EXIT,
          RUNTIME_SHUTDOWN_HOOK ->
          enforcer.check(caller, op, "test", 0);
    };
  }
}
