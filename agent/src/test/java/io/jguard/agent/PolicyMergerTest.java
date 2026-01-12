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
 * Tests for {@link PolicyMerger}.
 *
 * <p>These tests verify that policy merging works correctly with grant/deny semantics:
 *
 * <ul>
 *   <li>Grants from embedded and external policies are combined (union)
 *   <li>Denials remove capabilities from the effective policy (set difference)
 *   <li>Denials always win over grants
 *   <li>Missing external file = embedded policy applies unchanged
 *   <li>Global policy applies to all modules
 * </ul>
 */
@DisplayName("PolicyMerger")
class PolicyMergerTest {

  @TempDir Path tempDir;
  private Path externalDir;

  @BeforeEach
  void setUp() throws IOException {
    externalDir = tempDir.resolve("policies");
    Files.createDirectories(externalDir);
  }

  @Nested
  @DisplayName("Basic merge behavior")
  class BasicMerge {

    @Test
    @DisplayName("no external directory returns embedded policy unchanged")
    void noExternalDirReturnsEmbeddedUnchanged() throws IOException {
      ApplicationPolicy embedded = createEmbeddedPolicy();

      ApplicationPolicy merged = PolicyMerger.merge(embedded, null);

      assertThat(merged).isSameAs(embedded);
    }

    @Test
    @DisplayName("empty external directory returns embedded policy unchanged")
    void emptyExternalDirReturnsEmbeddedUnchanged() throws IOException {
      ApplicationPolicy embedded = createEmbeddedPolicy();

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      assertThat(merged.modules()).hasSize(1);
      assertThat(merged.modules().get(0).entitlements()).hasSize(3);
    }
  }

  @Nested
  @DisplayName("Grant semantics (union)")
  class GrantSemantics {

    @Test
    @DisplayName("external grants are added to embedded (union)")
    void externalGrantsAreAdded() throws IOException {
      // Embedded: fs.read only
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // External adds threads.create
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      assertThat(merged.modules()).hasSize(1);
      Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
      assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "threads.create");
    }

    @Test
    @DisplayName("global grants are added to all modules")
    void globalGrantsAreAddedToAllModules() throws IOException {
      // Embedded: two modules with only fs.read
      ModulePolicy moduleA =
          new ModulePolicy(
              "com.example.core",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
      ModulePolicy moduleB =
          new ModulePolicy(
              "com.example.network",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
      ApplicationPolicy embedded = ApplicationPolicy.create(List.of(moduleA, moduleB));

      // Global adds threads.create
      ModulePolicy global =
          new ModulePolicy(
              "_global",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of());
      writeExternalPolicy(PolicyMerger.GLOBAL_POLICY_FILENAME, global);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Both modules should now have fs.read AND threads.create
      for (ModulePolicy module : merged.modules()) {
        Set<String> capabilities = extractCapabilityNames(module);
        assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "threads.create");
      }
    }
  }

  @Nested
  @DisplayName("Deny semantics (set difference)")
  class DenySemantics {

    @Test
    @DisplayName("external denial removes embedded grant")
    void externalDenialRemovesEmbeddedGrant() throws IOException {
      // Embedded: fs.read, threads.create, network.outbound
      ApplicationPolicy embedded = createEmbeddedPolicy();

      // External denies network.outbound
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(), // no additional grants
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      assertThat(merged.modules()).hasSize(1);
      Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
      assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "threads.create");
    }

    @Test
    @DisplayName("global denial removes capability from all modules")
    void globalDenialRemovesFromAllModules() throws IOException {
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

      // Global denies threads.create
      ModulePolicy global =
          new ModulePolicy(
              "_global",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
      writeExternalPolicy(PolicyMerger.GLOBAL_POLICY_FILENAME, global);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Both modules should only have fs.read now
      for (ModulePolicy module : merged.modules()) {
        Set<String> capabilities = extractCapabilityNames(module);
        assertThat(capabilities).containsExactly("fs.read");
      }
    }

    @Test
    @DisplayName("denial with matching arguments removes specific grant")
    void denialWithArgumentsRemovesSpecificGrant() throws IOException {
      // Embedded: fs.read("/data", "**") and fs.read("/config", "*.json")
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(SubjectPattern.module(), fsReadCapability()),
                  new Entitlement(
                      SubjectPattern.module(),
                      CapabilityGrant.of(
                          "fs.read",
                          List.of(
                              new CapabilityArgument.StringArg("/config"),
                              new CapabilityArgument.StringArg("*.json"))))));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // External denies fs.read("/data", "**") specifically
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), fsReadCapability())));
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      // Only fs.read("/config", "*.json") should remain
      assertThat(merged.modules()).hasSize(1);
      List<Entitlement> entitlements = merged.modules().get(0).entitlements();
      assertThat(entitlements).hasSize(1);
      assertThat(entitlements.get(0).capability().arguments().get(0))
          .isEqualTo(new CapabilityArgument.StringArg("/config"));
    }

    @Test
    @DisplayName("module denial only affects that module")
    void moduleDenialOnlyAffectsThatModule() throws IOException {
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

      // External denies threads.create only for core module
      ModulePolicy external =
          new ModulePolicy(
              "com.example.core",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
      writeExternalPolicy("com.example.core.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embedded, externalDir);

      // Core should only have fs.read
      ModulePolicy mergedCore = merged.getModule("com.example.core").orElseThrow();
      assertThat(extractCapabilityNames(mergedCore)).containsExactly("fs.read");

      // Network should still have both
      ModulePolicy mergedNetwork = merged.getModule("com.example.network").orElseThrow();
      assertThat(extractCapabilityNames(mergedNetwork))
          .containsExactlyInAnyOrder("fs.read", "threads.create");
    }
  }

  @Nested
  @DisplayName("Subject pattern matching for denials")
  class SubjectPatternMatching {

    @Test
    @DisplayName("MODULE denial matches all subjects")
    void moduleDenialMatchesAllSubjects() throws IOException {
      // Embedded: grants to module, exact package, and recursive
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound")),
                  new Entitlement(
                      SubjectPattern.exactPackage("com.example.app.net"),
                      CapabilityGrant.of("network.outbound")),
                  new Entitlement(
                      SubjectPattern.recursive("com.example.app.http"),
                      CapabilityGrant.of("network.outbound"))));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // Deny network.outbound for entire module
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      // All network.outbound grants should be removed
      assertThat(merged.modules().get(0).entitlements()).isEmpty();
    }

    @Test
    @DisplayName("PACKAGE_RECURSIVE denial matches descendants")
    void recursiveDenialMatchesDescendants() throws IOException {
      // Embedded: grants to various packages under com.example.app
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(
                      SubjectPattern.exactPackage("com.example.app"),
                      CapabilityGrant.of("network.outbound")),
                  new Entitlement(
                      SubjectPattern.exactPackage("com.example.app.http"),
                      CapabilityGrant.of("network.outbound")),
                  new Entitlement(
                      SubjectPattern.exactPackage("com.example.app.http.client"),
                      CapabilityGrant.of("network.outbound")),
                  new Entitlement(
                      SubjectPattern.exactPackage("com.example.other"),
                      CapabilityGrant.of("network.outbound"))));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // Deny network.outbound for com.example.app..
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(),
              List.of(
                  Denial.of(
                      SubjectPattern.recursive("com.example.app"),
                      CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      // Only com.example.other should remain
      List<Entitlement> remaining = merged.modules().get(0).entitlements();
      assertThat(remaining).hasSize(1);
      assertThat(remaining.get(0).subject().packageName()).isEqualTo("com.example.other");
    }
  }

  @Nested
  @DisplayName("Combined grants and denials")
  class CombinedGrantsAndDenials {

    @Test
    @DisplayName("denial wins over grant in same external policy")
    void denialWinsOverGrantInSamePolicy() throws IOException {
      // Embedded: only fs.read
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // External grants threads.create but also denies it
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
      writeExternalPolicy("com.example.app.bin", external);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      // Only fs.read should remain (threads.create was granted then denied)
      Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
      assertThat(capabilities).containsExactly("fs.read");
    }

    @Test
    @DisplayName("grants are added and then denials are applied")
    void grantsAddedThenDenialsApplied() throws IOException {
      // Embedded: fs.read
      ModulePolicy embedded =
          new ModulePolicy(
              "com.example.app",
              List.of(new Entitlement(SubjectPattern.module(), fsReadCapability())));
      ApplicationPolicy embeddedPolicy = ApplicationPolicy.single(embedded);

      // External grants threads.create and network.outbound
      ModulePolicy external =
          new ModulePolicy(
              "com.example.app",
              List.of(
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create")),
                  new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))),
              List.of());
      writeExternalPolicy("com.example.app.bin", external);

      // Global denies network.outbound
      ModulePolicy global =
          new ModulePolicy(
              "_global",
              List.of(),
              List.of(Denial.of(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));
      writeExternalPolicy(PolicyMerger.GLOBAL_POLICY_FILENAME, global);

      ApplicationPolicy merged = PolicyMerger.merge(embeddedPolicy, externalDir);

      // fs.read (embedded) + threads.create (external) - network.outbound (global denial)
      Set<String> capabilities = extractCapabilityNames(merged.modules().get(0));
      assertThat(capabilities).containsExactlyInAnyOrder("fs.read", "threads.create");
    }
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
}
