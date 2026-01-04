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
import org.jguard.bootstrap.CallerContext;
import org.jguard.bootstrap.EnforcementMode;
import org.jguard.bootstrap.Operation;
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
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.sub"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("access denied")
          .hasMessageContaining("fs.read");
    }

    @Test
    @DisplayName("denies access to paths outside the entitled root")
    void deniesOutsideRoot() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), outsideFile))
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

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.io"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app.io.impl"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app.other"), dataFile))
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

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.io"), dataFile))
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

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.io.impl"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.io.impl.deep"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app.other"), dataFile))
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

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.io"), dataFile))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app.worker"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app.io.impl"), dataFile))
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

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app"), jsonFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects non-matching extension")
    void rejectsNonMatchingExtension() {
      Path xmlFile = tempDir.resolve("config.xml");
      PolicyDescriptor policy =
          createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*.json"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), xmlFile))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("matches recursive glob pattern")
    void matchesRecursiveGlob() {
      PolicyDescriptor policy =
          createPolicy("com.example.app", fsReadEntitlement(dataRoot, "**/*.json"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app"), dataSubFile))
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
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();

      // Second call should hit cache
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("caches deny decisions")
    void cachesDenyDecisions() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      // First call
      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .isInstanceOf(SecurityException.class);

      // Second call should hit cache
      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
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
              () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("allows access from unnamed module (classpath)")
    void allowsUnnamedModule() {
      PolicyDescriptor policy = createPolicy("com.example.app", fsReadEntitlement(dataRoot, "*"));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Unnamed modules (classpath) are allowed - package check still applies
      assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app", "unnamed"), dataFile))
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
                  checkFsRead(
                      enforcer, caller("com.example.app", "com.malicious.module"), dataFile))
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

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app.io"), dataFile))
          .hasMessageContaining("com.example.app.io");
    }

    @Test
    @DisplayName("includes capability name in error")
    void includesCapabilityName() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), dataFile))
          .hasMessageContaining("fs.read");
    }

    @Test
    @DisplayName("includes path in error")
    void includesPath() {
      Path secretFile = tempDir.resolve("secret.txt");
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkFsRead(enforcer, caller("com.example.app"), secretFile))
          .hasMessageContaining("secret.txt");
    }
  }

  @Nested
  @DisplayName("SIMPLE category operations (threads.create, network.outbound)")
  class SimpleOperationTest {

    @Test
    @DisplayName("allows threads.create when module is entitled")
    void allowsThreadsCreate() {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(
              () -> checkOperation(enforcer, caller("com.example.app"), Operation.THREAD_CREATE))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies threads.create when not entitled")
    void deniesThreadsCreate() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(
              () -> checkOperation(enforcer, caller("com.example.app"), Operation.THREAD_CREATE))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("threads.create");
    }

    @Test
    @DisplayName("allows network.outbound when entitled")
    void allowsNetworkOutbound() {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatCode(
              () -> checkOperation(enforcer, caller("com.example.app"), Operation.NET_CONNECT))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies network.outbound when not entitled")
    void deniesNetworkOutbound() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(
              () -> checkOperation(enforcer, caller("com.example.app"), Operation.NET_CONNECT))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("network.outbound");
    }

    @Test
    @DisplayName("respects package scope for threads.create")
    void respectsPackageScopeForThreadsCreate() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example.app.worker"),
              CapabilityGrant.of("threads.create"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Entitled package allowed
      assertThatCode(
              () ->
                  checkOperation(
                      enforcer, caller("com.example.app.worker"), Operation.THREAD_CREATE))
          .doesNotThrowAnyException();

      // Other packages denied
      assertThatThrownBy(
              () -> checkOperation(enforcer, caller("com.example.app"), Operation.THREAD_CREATE))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("TARGET_PATTERN category operations (native.load)")
  class TargetPatternOperationTest {

    @Test
    @DisplayName("allows native.load when entitled with no pattern restriction")
    void allowsNativeLoadAnyTarget() {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("native.load"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Any library should be allowed
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libcrypto"))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libssl"))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies native.load when not entitled")
    void deniesNativeLoad() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libnative"))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("native.load");
    }

    @Test
    @DisplayName("allows native.load with exact pattern match")
    void allowsNativeLoadExactPattern() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.module(),
              CapabilityGrant.of(
                  "native.load", List.of(new CapabilityArgument.StringArg("libcrypto"))));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Exact match allowed
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libcrypto"))
          .doesNotThrowAnyException();

      // Non-matching denied
      assertThatThrownBy(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libssl"))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("allows native.load with wildcard pattern")
    void allowsNativeLoadWildcardPattern() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.module(),
              CapabilityGrant.of(
                  "native.load", List.of(new CapabilityArgument.StringArg("lib.*"))));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Direct children of lib. pattern allowed
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "lib.crypto"))
          .doesNotThrowAnyException();

      // lib.sub.foo would NOT match (only one segment after lib.)
      assertThatThrownBy(() -> checkNativeLoad(enforcer, caller("com.example.app"), "lib.sub.foo"))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("allows native.load with recursive pattern")
    void allowsNativeLoadRecursivePattern() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.module(),
              CapabilityGrant.of(
                  "native.load", List.of(new CapabilityArgument.StringArg("lib.**"))));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // All descendants of lib allowed
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "lib.crypto"))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app"), "lib.sub.deep.foo"))
          .doesNotThrowAnyException();

      // Non-matching denied
      assertThatThrownBy(() -> checkNativeLoad(enforcer, caller("com.example.app"), "other.lib"))
          .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("respects package scope for native.load")
    void respectsPackageScopeForNativeLoad() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.exactPackage("com.example.app.native"),
              CapabilityGrant.of("native.load"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Entitled package allowed
      assertThatCode(() -> checkNativeLoad(enforcer, caller("com.example.app.native"), "libfoo"))
          .doesNotThrowAnyException();

      // Other packages denied
      assertThatThrownBy(() -> checkNativeLoad(enforcer, caller("com.example.app"), "libfoo"))
          .isInstanceOf(SecurityException.class);
    }
  }

  @Nested
  @DisplayName("PORT category operations (network.listen)")
  class PortOperationTest {

    @Test
    @DisplayName("allows network.listen when entitled with no port restriction")
    void allowsNetworkListenAnyPort() {
      Entitlement entitlement =
          new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.listen"));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Any port should be allowed
      assertThatCode(() -> checkNetworkListen(enforcer, caller("com.example.app"), 8080))
          .doesNotThrowAnyException();
      assertThatCode(() -> checkNetworkListen(enforcer, caller("com.example.app"), 443))
          .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("denies network.listen when not entitled")
    void deniesNetworkListen() {
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of());

      PolicyEnforcer enforcer = createEnforcer(policy);

      assertThatThrownBy(() -> checkNetworkListen(enforcer, caller("com.example.app"), 8080))
          .isInstanceOf(SecurityException.class)
          .hasMessageContaining("network.listen");
    }

    @Test
    @DisplayName("allows network.listen with specific port restriction")
    void allowsNetworkListenSpecificPort() {
      Entitlement entitlement =
          new Entitlement(
              SubjectPattern.module(),
              CapabilityGrant.of(
                  "network.listen", List.of(new CapabilityArgument.IntegerArg(8080))));
      PolicyDescriptor policy = PolicyDescriptor.create("com.example.app", List.of(entitlement));

      PolicyEnforcer enforcer = createEnforcer(policy);

      // Exact port match allowed
      assertThatCode(() -> checkNetworkListen(enforcer, caller("com.example.app"), 8080))
          .doesNotThrowAnyException();

      // Ephemeral port (0) allowed with any entitlement
      assertThatCode(() -> checkNetworkListen(enforcer, caller("com.example.app"), 0))
          .doesNotThrowAnyException();

      // Different port denied
      assertThatThrownBy(() -> checkNetworkListen(enforcer, caller("com.example.app"), 9090))
          .isInstanceOf(SecurityException.class);
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

  /** Helper to call check() and throw if denied, for test readability. */
  private static void checkFsRead(PolicyEnforcer enforcer, CallerContext caller, Path path) {
    SecurityException denial = enforcer.check(caller, Operation.FS_READ, path, 0);
    if (denial != null) {
      throw denial;
    }
  }

  /** Helper for SIMPLE category operations (threads.create, network.outbound). */
  private static void checkOperation(PolicyEnforcer enforcer, CallerContext caller, Operation op) {
    SecurityException denial = enforcer.check(caller, op, "test", 0);
    if (denial != null) {
      throw denial;
    }
  }

  /** Helper for native.load operations. */
  private static void checkNativeLoad(
      PolicyEnforcer enforcer, CallerContext caller, String libraryName) {
    SecurityException denial = enforcer.check(caller, Operation.NATIVE_LOAD, libraryName, 0);
    if (denial != null) {
      throw denial;
    }
  }

  /** Helper for network.listen operations. */
  private static void checkNetworkListen(PolicyEnforcer enforcer, CallerContext caller, int port) {
    SecurityException denial = enforcer.check(caller, Operation.NET_LISTEN, null, port);
    if (denial != null) {
      throw denial;
    }
  }
}
