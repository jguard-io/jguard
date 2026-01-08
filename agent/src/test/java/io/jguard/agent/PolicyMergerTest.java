/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for {@link PolicyMerger}.
 *
 * <p>These tests verify that policy overrides work correctly:
 *
 * <ul>
 *   <li>Overrides can only RESTRICT capabilities (intersection)
 *   <li>Overrides cannot GRANT new capabilities
 *   <li>Missing override = full embedded policy applies
 *   <li>Global override applies to all modules
 *   <li>Module-specific override applies only to that module
 * </ul>
 */
@DisplayName("PolicyMerger")
class PolicyMergerTest {

  @TempDir Path tempDir;
  private Path overrideDir;

  @BeforeEach
  void setUp() throws IOException {
    overrideDir = tempDir.resolve("overrides");
    Files.createDirectories(overrideDir);
  }

  @Test
  @DisplayName("no override directory returns embedded policy unchanged")
  void noOverrideDirReturnsEmbeddedUnchanged() throws IOException {
    ApplicationPolicy embedded = createEmbeddedPolicy();

    ApplicationPolicy merged = PolicyMerger.merge(embedded, null);

    assertThat(merged).isSameAs(embedded);
  }

  @Test
  @DisplayName("empty override directory returns embedded policy unchanged")
  void emptyOverrideDirReturnsEmbeddedUnchanged() throws IOException {
    ApplicationPolicy embedded = createEmbeddedPolicy();

    ApplicationPolicy merged = PolicyMerger.merge(embedded, overrideDir);

    assertThat(merged.modules()).hasSize(1);
    assertThat(merged.modules().get(0).entitlements()).hasSize(3);
  }

  @Test
  @DisplayName("module override restricts capabilities (intersection)")
  void moduleOverrideRestrictsCapabilities() throws IOException {
    // Embedded: fs.read, threads.create, network.outbound
    ApplicationPolicy embedded = createEmbeddedPolicy();

    // Override: only fs.read (removes threads.create and network.outbound)
    ModulePolicy override =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
    writeOverride("com.example.app.bin", override);

    ApplicationPolicy merged = PolicyMerger.merge(embedded, overrideDir);

    assertThat(merged.modules()).hasSize(1);
    Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
    assertThat(capabilities).containsExactly("fs.read");
  }

  @Test
  @DisplayName("global override restricts all modules")
  void globalOverrideRestrictsAllModules() throws IOException {
    // Embedded: two modules with different capabilities
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.core",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ModulePolicy moduleB =
        new ModulePolicy(
            "com.example.network",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
    ApplicationPolicy embedded = ApplicationPolicy.create(List.of(moduleA, moduleB));

    // Global override: only fs.read
    ModulePolicy globalOverride =
        new ModulePolicy(
            "_global", List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
    writeOverride(PolicyMerger.GLOBAL_OVERRIDE_FILENAME, globalOverride);

    ApplicationPolicy merged = PolicyMerger.merge(embedded, overrideDir);

    assertThat(merged.modules()).hasSize(2);
    // Both modules should only have fs.read now
    for (ModulePolicy module : merged.modules()) {
      Set<String> capabilities = extractCapabilityNames(module);
      assertThat(capabilities).containsExactly("fs.read");
    }
  }

  @Test
  @DisplayName("module-specific override only affects that module")
  void moduleSpecificOverrideOnlyAffectsThatModule() throws IOException {
    // Embedded: two modules with same capabilities
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.core",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ModulePolicy moduleB =
        new ModulePolicy(
            "com.example.network",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ApplicationPolicy embedded = ApplicationPolicy.create(List.of(moduleA, moduleB));

    // Override only core module: remove threads.create
    ModulePolicy coreOverride =
        new ModulePolicy(
            "com.example.core",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
    writeOverride("com.example.core.bin", coreOverride);

    ApplicationPolicy merged = PolicyMerger.merge(embedded, overrideDir);

    assertThat(merged.modules()).hasSize(2);
    // Core module should only have fs.read
    ModulePolicy mergedCore = merged.getModule("com.example.core").orElseThrow();
    assertThat(extractCapabilityNames(mergedCore)).containsExactly("fs.read");
    // Network module should still have both
    ModulePolicy mergedNetwork = merged.getModule("com.example.network").orElseThrow();
    assertThat(extractCapabilityNames(mergedNetwork))
        .containsExactlyInAnyOrder("fs.read", "threads.create");
  }

  @Test
  @DisplayName("both module and global overrides are applied (intersection)")
  void bothModuleAndGlobalOverridesApplied() throws IOException {
    // Embedded: fs.read, threads.create, network.outbound
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create")),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
    ApplicationPolicy embedded = ApplicationPolicy.single(moduleA);

    // Module override: fs.read, threads.create (removes network.outbound)
    ModulePolicy moduleOverride =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    writeOverride("com.example.app.bin", moduleOverride);

    // Global override: fs.read, network.outbound (removes threads.create)
    ModulePolicy globalOverride =
        new ModulePolicy(
            "_global",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
    writeOverride(PolicyMerger.GLOBAL_OVERRIDE_FILENAME, globalOverride);

    ApplicationPolicy merged = PolicyMerger.merge(embedded, overrideDir);

    // Result should be intersection: only fs.read
    assertThat(merged.modules()).hasSize(1);
    Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
    assertThat(capabilities).containsExactly("fs.read");
  }

  @Test
  @DisplayName("validate override detects entitlements not in embedded")
  void validateOverrideDetectsExtraEntitlements() {
    // Embedded: only fs.read
    ModulePolicy embedded =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));

    // Override tries to add threads.create (not in embedded)
    ModulePolicy override =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));

    PolicyMerger.ValidationResult result = PolicyMerger.validateOverride(embedded, override);

    assertThat(result.valid()).isFalse();
    assertThat(result.invalidEntitlements()).hasSize(1);
    assertThat(result.invalidEntitlements().get(0).capability().name()).isEqualTo("threads.create");
  }

  @Test
  @DisplayName("validate override passes when override is subset")
  void validateOverridePassesWhenSubset() {
    // Embedded: fs.read, threads.create
    ModulePolicy embedded =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability()),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));

    // Override: only fs.read (valid subset)
    ModulePolicy override =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));

    PolicyMerger.ValidationResult result = PolicyMerger.validateOverride(embedded, override);

    assertThat(result.valid()).isTrue();
    assertThat(result.invalidEntitlements()).isEmpty();
  }

  // ===== Helper methods =====

  private ApplicationPolicy createEmbeddedPolicy() {
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

  private void writeOverride(String filename, ModulePolicy policy) throws IOException {
    Path overridePath = overrideDir.resolve(filename);
    ApplicationPolicy appPolicy = ApplicationPolicy.single(policy);
    try (FileOutputStream fos = new FileOutputStream(overridePath.toFile())) {
      BinaryPolicyWriter.write(appPolicy, fos);
    }
  }

  private Set<String> extractCapabilityNames(ModulePolicy module) {
    return module.entitlements().stream()
        .map(e -> e.capability().name())
        .collect(Collectors.toSet());
  }
}
