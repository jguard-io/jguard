/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.CallerContext;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.bootstrap.Operation;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Denial;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.SubjectPattern;
import io.jguard.policy.serialization.BinaryPolicyWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for legacy library support - modules without embedded jGuard policies.
 *
 * <p>This tests the scenario where:
 *
 * <ul>
 *   <li>A third-party library has no embedded jGuard policy
 *   <li>The library may be an automatic module (JAR without module-info.java)
 *   <li>External policies can grant capabilities to these legacy modules
 *   <li>The MODULE pattern must match packages that don't follow naming conventions
 * </ul>
 */
@DisplayName("Legacy Library Support")
class LegacyLibrarySupportTest {

  @TempDir Path tempDir;
  private Path externalDir;

  @BeforeEach
  void setUp() throws IOException {
    externalDir = tempDir.resolve("policies");
    Files.createDirectories(externalDir);
  }

  @Nested
  @DisplayName("PolicyMerger: External policies for new modules")
  class PolicyMergerNewModules {

    @Test
    @DisplayName("external policy creates new module when no embedded policy exists")
    void externalPolicyCreatesNewModule() throws IOException {
      // Embedded: only has com.example.app module
      ApplicationPolicy embedded = createAppPolicy();

      // External policy for a completely new module (legacy library)
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), fsReadCapability()),
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Should have both modules
      assertThat(merged.modules()).hasSize(2);

      // Original module should be unchanged
      assertThat(merged.hasModule("com.example.app")).isTrue();

      // Legacy module should be added
      assertThat(merged.hasModule("legacy.library")).isTrue();
      ModulePolicy legacy = merged.getModule("legacy.library").orElseThrow();
      Set<String> capabilities = extractCapabilityNames(legacy);
      assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "threads.create");
    }

    @Test
    @DisplayName("global denials apply to legacy modules")
    void globalDenialsApplyToLegacyModules() throws IOException {
      ApplicationPolicy embedded = createAppPolicy();

      // External policy for legacy library with threads.create
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), fsReadCapability()),
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      // Global denies threads.create
      ModulePolicy global =
          new ModulePolicy(
              "_global",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
      writeExternalPolicy(PolicyMerger.GLOBAL_POLICY_FILENAME, global);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Legacy module should have threads.create denied
      ModulePolicy legacy = merged.getModule("legacy.library").orElseThrow();
      Set<String> capabilities = extractCapabilityNames(legacy);
      assertThat(capabilities).containsExactly("fs.read");
    }

    @Test
    @DisplayName("global grants apply to legacy modules")
    void globalGrantsApplyToLegacyModules() throws IOException {
      ApplicationPolicy embedded = createAppPolicy();

      // External policy for legacy library with only fs.read
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      // Global grants system.property.read
      ModulePolicy global =
          new ModulePolicy(
              "_global",
              List.of(
                  new Entitlement(
                      SubjectPattern.module(), CapabilityGrant.of("system.property.read"))),
              List.of());
      writeExternalPolicy(PolicyMerger.GLOBAL_POLICY_FILENAME, global);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Legacy module should have both fs.read and system.property.read
      ModulePolicy legacy = merged.getModule("legacy.library").orElseThrow();
      Set<String> capabilities = extractCapabilityNames(legacy);
      assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "system.property.read");
    }

    @Test
    @DisplayName("multiple legacy modules can be added")
    void multipleLegacyModulesCanBeAdded() throws IOException {
      ApplicationPolicy embedded = createAppPolicy();

      // External policies for multiple legacy libraries
      ModulePolicy legacy1 =
          new ModulePolicy(
              "legacy.library.one",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())),
              List.of());
      ModulePolicy legacy2 =
          new ModulePolicy(
              "legacy.library.two",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("legacy.library.one.bin", legacy1);
      writeExternalPolicy("legacy.library.two.bin", legacy2);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Should have all three modules
      assertThat(merged.modules()).hasSize(3);
      assertThat(merged.hasModule("com.example.app")).isTrue();
      assertThat(merged.hasModule("legacy.library.one")).isTrue();
      assertThat(merged.hasModule("legacy.library.two")).isTrue();
    }
  }

  @Nested
  @DisplayName("PolicyEnforcer: MODULE pattern for automatic modules")
  class AutomaticModulePatternMatching {

    @Test
    @DisplayName("MODULE pattern matches packages that don't follow module naming convention")
    void modulePatternMatchesNonConventionalPackages() {
      // Simulate an automatic module where:
      // - Module name: "legacy.library" (derived from JAR filename legacy-library.jar)
      // - Package name: "io.vendor.library" (doesn't start with module name!)
      ModulePolicy legacyModule =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      ApplicationPolicy policy = ApplicationPolicy.single(legacyModule);

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Caller from package "io.vendor.library" in module "legacy.library"
      // Package name does NOT start with module name - this is the automatic module case
      CallerContext caller = new CallerContext("io.vendor.library", "legacy.library");

      assertThatCode(() -> checkOperation(enforcer, caller, Operation.THREAD_CREATE))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("MODULE pattern matches deeply nested packages in automatic modules")
    void modulePatternMatchesDeeplyNestedPackages() {
      ModulePolicy legacyModule =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))),
              List.of());
      ApplicationPolicy policy = ApplicationPolicy.single(legacyModule);

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Deep package that doesn't match module name at all
      CallerContext caller = new CallerContext("com.thirdparty.internal.impl", "legacy.library");

      assertThatCode(() -> checkNetworkOutbound(enforcer, caller, "example.com", 80))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access when caller module doesn't match policy module")
    void deniesWhenModuleDoesntMatch() {
      ModulePolicy legacyModule =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      ApplicationPolicy policy = ApplicationPolicy.single(legacyModule);

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Caller claims to be from a different module
      CallerContext caller = new CallerContext("io.vendor.library", "some.other.module");

      assertThatThrownBy(() -> checkOperation(enforcer, caller, Operation.THREAD_CREATE))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("no policy for module");
    }

    @Test
    @DisplayName("PACKAGE_EXACT pattern still works for specific package grants")
    void packageExactStillWorks() {
      // Even in automatic modules, package-specific grants should work
      ModulePolicy legacyModule =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(
                      SubjectPattern.exactPackage("io.vendor.library.net"),
                      CapabilityGrant.of("network.outbound"))),
              List.of());
      ApplicationPolicy policy = ApplicationPolicy.single(legacyModule);

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Exact package match allowed
      CallerContext allowedCaller = new CallerContext("io.vendor.library.net", "legacy.library");
      assertThatCode(() -> checkNetworkOutbound(enforcer, allowedCaller, "example.com", 80))
          .doesNotThrowAnyException();

      // Different package denied
      CallerContext deniedCaller = new CallerContext("io.vendor.library.other", "legacy.library");
      assertThatThrownBy(() -> checkNetworkOutbound(enforcer, deniedCaller, "example.com", 80))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("PACKAGE_RECURSIVE pattern works for automatic modules")
    void packageRecursiveWorksForAutomaticModules() {
      ModulePolicy legacyModule =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(
                      SubjectPattern.recursive("io.vendor"), CapabilityGrant.of("threads.create"))),
              List.of());
      ApplicationPolicy policy = ApplicationPolicy.single(legacyModule);

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Base package allowed
      CallerContext baseCaller = new CallerContext("io.vendor", "legacy.library");
      assertThatCode(() -> checkOperation(enforcer, baseCaller, Operation.THREAD_CREATE))
          .doesNotThrowAnyException();

      // Child package allowed
      CallerContext childCaller = new CallerContext("io.vendor.library.impl", "legacy.library");
      assertThatCode(() -> checkOperation(enforcer, childCaller, Operation.THREAD_CREATE))
          .doesNotThrowAnyException();

      // Different package tree denied
      CallerContext otherCaller = new CallerContext("com.other.package", "legacy.library");
      assertThatThrownBy(() -> checkOperation(enforcer, otherCaller, Operation.THREAD_CREATE))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("End-to-end: Legacy library with external policy")
  class EndToEndLegacyLibrary {

    @Test
    @DisplayName("complete flow: external policy for legacy module enables enforcement")
    void completeFlowLegacyModuleEnforcement() throws IOException {
      // Step 1: Create embedded policy for main app
      ApplicationPolicy embedded = createAppPolicy();

      // Step 2: Create external policy for legacy library
      ModulePolicy legacyPolicy =
          new ModulePolicy(
              "legacy.library",
              List.of(
                  new Entitlement(SubjectPattern.module(), fsReadCapability()),
                  new Entitlement(
                      SubjectPattern.module(), CapabilityGrant.of("system.property.read"))),
              List.of());
      writeExternalPolicy("legacy.library.bin", legacyPolicy);

      // Step 3: Merge policies
      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Step 4: Create enforcer with merged policy
      PolicyEnforcer enforcer = createEnforcer(merged);

      // Step 5: Verify enforcement for legacy module
      // Caller from automatic module (package doesn't match module name)
      CallerContext legacyCaller =
          new CallerContext("io.vendor.legacy.library.internal", "legacy.library");

      // Granted capabilities allowed
      assertThatCode(() -> checkPropertyRead(enforcer, legacyCaller, "java.version"))
          .doesNotThrowAnyException();

      // Non-granted capabilities denied
      assertThatThrownBy(() -> checkOperation(enforcer, legacyCaller, Operation.THREAD_CREATE))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("threads.create");

      assertThatThrownBy(() -> checkNetworkOutbound(enforcer, legacyCaller, "example.com", 80))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("network.outbound");
    }
  }

  // ===== Helper methods =====

  private ApplicationPolicy createAppPolicy() {
    ModulePolicy module =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create")),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
    return ApplicationPolicy.single(module);
  }

  private CapabilityGrant fsReadCapability() {
    return CapabilityGrant.of(
        "fs.read",
        List.of(new CapabilityArgument.StringArg("/data"), new CapabilityArgument.StringArg("**")));
  }

  private void writeExternalPolicy(String filename, ModulePolicy policy) throws IOException {
    Path policyPath = externalDir.resolve(filename);
    ApplicationPolicy appPolicy = ApplicationPolicy.single(policy);
    try (FileOutputStream fos = new FileOutputStream(policyPath.toFile())) {
      BinaryPolicyWriter.write(appPolicy, fos);
    }
  }

  private Set<String> extractCapabilityNames(ModulePolicy module) {
    return module.entitlements().stream()
        .map(e -> e.capability().name())
        .collect(Collectors.toSet());
  }

  private PolicyEnforcer createEnforcer(ApplicationPolicy policy) {
    AgentConfig config =
        new AgentConfig.Builder()
            .policyPath(tempDir.resolve("policy.bin"))
            .mode(EnforcementMode.STRICT)
            .build();
    return new PolicyEnforcer(policy, config);
  }

  private static void checkOperation(PolicyEnforcer enforcer, CallerContext caller, Operation op) {
    SecurityException denial = enforcer.check(caller, op, "test", 0);
    if (denial != null) {
      throw denial;
    }
  }

  private static void checkNetworkOutbound(
      PolicyEnforcer enforcer, CallerContext caller, String host, int port) {
    SecurityException denial = enforcer.check(caller, Operation.NET_CONNECT, host, port);
    if (denial != null) {
      throw denial;
    }
  }

  private static void checkPropertyRead(PolicyEnforcer enforcer, CallerContext caller, String key) {
    SecurityException denial = enforcer.check(caller, Operation.PROP_READ, key, 0);
    if (denial != null) {
      throw denial;
    }
  }
}
