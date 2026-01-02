/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import org.jguard.bootstrap.AgentConfig;
import org.jguard.bootstrap.BootstrapEnforcer.CallerContext;
import org.jguard.bootstrap.EnforcementMode;
import org.jguard.policy.model.CapabilityArgument;
import org.jguard.policy.model.CapabilityGrant;
import org.jguard.policy.model.Entitlement;
import org.jguard.policy.model.PolicyDescriptor;
import org.jguard.policy.model.SubjectPattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests for {@link PolicyEnforcer}. */
class PolicyEnforcerTest {

  @TempDir Path tempDir;

  private String dataRoot;
  private Path dataFile;
  private Path dataSubFile;
  private Path outsideFile;

  @BeforeEach
  void setUp() {
    // Use tempDir as our test root - this is a real absolute path that exists
    dataRoot = tempDir.toString();
    dataFile = tempDir.resolve("file.txt");
    dataSubFile = tempDir.resolve("sub/config.json");
    outsideFile = tempDir.getParent().resolve("outside.txt");
  }

  @Nested
  @DisplayName("Module-wide entitlements")
  class ModuleEntitlementTest {

    @Test
    @DisplayName("allows access when module is entitled to fs.read")
    void allowsModuleWideAccess() {
      // Use pattern that matches direct files (not just subdirectory files)
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Any package in the module should be allowed
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.sub"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access when module is not entitled")
    void deniesWhenNotEntitled() {
      PolicyDescriptor policy =
          PolicyDescriptor.create(
              "com.example.app",
              List.of(
                  new Entitlement(
                      SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("access denied")
          .hasMessageContaining("fs.read");
    }

    @Test
    @DisplayName("denies access to paths outside the entitled root")
    void deniesOutsideRoot() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), outsideFile))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("access denied");
    }
  }

  @Nested
  @DisplayName("Package-exact entitlements")
  class ExactPackageEntitlementTest {

    @Test
    @DisplayName("allows access for exact package match")
    void allowsExactPackage() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.io"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access for subpackages of exact package")
    void deniesSubpackages() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app.io.impl"), dataFile))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("denies access for unrelated packages")
    void deniesUnrelatedPackages() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app.other"), dataFile))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("Package-recursive entitlements")
  class RecursivePackageEntitlementTest {

    @Test
    @DisplayName("allows access for exact package")
    void allowsExactPackage() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.io"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("allows access for subpackages")
    void allowsSubpackages() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.io.impl"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.io.impl.deep"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access for sibling packages")
    void deniesSiblingPackages() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.recursive("com.example.app.io"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app.other"), dataFile))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("Direct children entitlements")
  class DirectChildrenEntitlementTest {

    @Test
    @DisplayName("allows access for direct child packages")
    void allowsDirectChildren() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example.app"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.io"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app.worker"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access for parent package")
    void deniesParentPackage() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example.app"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("denies access for grandchild packages")
    void deniesGrandchildren() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.directChildren("com.example.app"), fsReadCapability(dataRoot, "*"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app.io.impl"), dataFile))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("Glob pattern matching")
  class GlobPatternTest {

    @Test
    @DisplayName("matches specific file extension")
    void matchesFileExtension() {
      Path jsonFile = tempDir.resolve("config.json");
      PolicyDescriptor policy =
          createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*.json"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app"), jsonFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects non-matching extension")
    void rejectsNonMatchingExtension() {
      Path xmlFile = tempDir.resolve("config.xml");
      PolicyDescriptor policy =
          createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*.json"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), xmlFile))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("matches recursive glob pattern")
    void matchesRecursiveGlob() {
      PolicyDescriptor policy =
          createPolicy("com.example.app", fsReadEntitlement(dataRoot, "**/*.json"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app"), dataSubFile))
          .doesNotThrowAnyException();
    }
  }

  @Nested
  @DisplayName("Decision caching")
  class DecisionCacheTest {

    @Test
    @DisplayName("caches allow decisions")
    void cachesAllowDecisions() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // First call
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();

      // Second call should hit cache
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("caches deny decisions")
    void cachesDenyDecisions() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      // First call
      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class);

      // Second call should hit cache
      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("Module verification")
  class ModuleVerificationTest {

    @Test
    @DisplayName("allows access from matching module")
    void allowsMatchingModule() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Module matches policy module
      assertThatCode(
              () -> enforcer.checkFsRead(caller("com.example.app", "com.example.app"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("allows access from unnamed module (classpath)")
    void allowsUnnamedModule() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Unnamed modules (classpath) are allowed - package check still applies
      assertThatCode(() -> enforcer.checkFsRead(caller("com.example.app", "unnamed"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies access from different named module")
    void deniesDifferentModule() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Module mismatch - even if package matches, should be denied
      assertThatThrownBy(
              () ->
                  enforcer.checkFsRead(caller("com.example.app", "com.malicious.module"), dataFile))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("module")
          .hasMessageContaining("com.malicious.module");
    }
  }

  @Nested
  @DisplayName("Error messages")
  class ErrorMessageTest {

    @Test
    @DisplayName("includes package name in error")
    void includesPackageName() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app.io"), dataFile))
          .hasMessageContaining("com.example.app.io");
    }

    @Test
    @DisplayName("includes capability name in error")
    void includesCapabilityName() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), dataFile))
          .hasMessageContaining("fs.read");
    }

    @Test
    @DisplayName("includes path in error")
    void includesPath() {
      Path secretFile = tempDir.resolve("secret.txt");
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> enforcer.checkFsRead(caller("com.example.app"), secretFile))
          .hasMessageContaining("secret.txt");
    }
  }

  // ===== Helper methods =====

  private Entitlement fsReadEntitlement(String root, String glob) {
    return new Entitlement(SubjectPattern.module(), fsReadCapability(root, glob));
  }

  private CapabilityGrant fsReadCapability(String root, String glob) {
    return CapabilityGrant.of(
        "fs.read",
        List.of(new CapabilityArgument.StringArg(root), new CapabilityArgument.StringArg(glob)));
  }

  private PolicyDescriptor createPolicy(String moduleName, Entitlement entitlement) {
    return PolicyDescriptor.create(moduleName, List.of(entitlement));
  }

  private PolicyEnforcer createEnforcer(PolicyDescriptor policy) {
    AgentConfig config =
        new AgentConfig.Builder()
            .policyPath(tempDir.resolve("policy.bin"))
            .mode(EnforcementMode.STRICT)
            .build();
    return new PolicyEnforcer(policy, config);
  }

  /**
   * Creates a CallerContext for the given package within the default test module.
   *
   * <p>For tests, we use the module name from the policy to simulate a matching module.
   */
  private CallerContext caller(String packageName, String moduleName) {
    return new CallerContext(packageName, moduleName);
  }

  /** Creates a CallerContext for the default module (com.example.app). */
  private CallerContext caller(String packageName) {
    return caller(packageName, "com.example.app");
  }
}
