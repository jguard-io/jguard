/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jguard.bootstrap.AgentConfig;
import io.jguard.bootstrap.CallerContext;
import io.jguard.bootstrap.EnforcementMode;
import io.jguard.bootstrap.Operation;
import io.jguard.policy.model.ApplicationPolicy;
import io.jguard.policy.model.CapabilityArgument;
import io.jguard.policy.model.CapabilityGrant;
import io.jguard.policy.model.Entitlement;
import io.jguard.policy.model.ModulePolicy;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.model.SubjectPattern;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for multi-module enforcement in {@link PolicyEnforcer}.
 *
 * <p>These tests verify that ApplicationPolicy (v2 multi-module format) works correctly with
 * PolicyEnforcer, including module isolation, cross-module access denial, and backward
 * compatibility with single-module (v1) policies.
 */
@DisplayName("Multi-module enforcement (ApplicationPolicy)")
class MultiModuleEnforcementTest {

  @TempDir Path tempDir;

  private String dataRoot;
  private Path dataFile;

  @BeforeEach
  void setUp() {
    dataRoot = tempDir.toString();
    dataFile = tempDir.resolve("file.txt");
  }

  @Test
  @DisplayName("each module uses only its own entitlements")
  void eachModuleUsesOwnEntitlements() {
    // Module A can read files, Module B can create threads
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));
    ModulePolicy moduleB =
        new ModulePolicy(
            "com.example.worker",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));

    ApplicationPolicy policy = ApplicationPolicy.create(List.of(moduleA, moduleB));
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Module A can read files
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
        .doesNotThrowAnyException();

    // Module A cannot create threads
    assertThatThrownBy(
            () ->
                checkOperation(
                    enforcer,
                    caller("com.example.app", "com.example.app"),
                    Operation.THREAD_CREATE))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("threads.create");

    // Module B can create threads
    assertThatCode(
            () ->
                checkOperation(
                    enforcer,
                    caller("com.example.worker", "com.example.worker"),
                    Operation.THREAD_CREATE))
        .doesNotThrowAnyException();

    // Module B cannot read files
    assertThatThrownBy(
            () ->
                checkFsRead(enforcer, caller("com.example.worker", "com.example.worker"), dataFile))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("fs.read");
  }

  @Test
  @DisplayName("cross-module access is denied")
  void crossModuleAccessDenied() {
    // Module A is entitled to read files
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));

    ApplicationPolicy policy = ApplicationPolicy.single(moduleA);
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Module A can access its own entitlement
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
        .doesNotThrowAnyException();

    // Module B (different named module) cannot use Module A's entitlement
    assertThatThrownBy(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.other"), dataFile))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("module")
        .hasMessageContaining("com.example.other");
  }

  @Test
  @DisplayName("module with no policy gets denied")
  void moduleWithNoPolicyDenied() {
    // Only module A has a policy
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));

    ApplicationPolicy policy = ApplicationPolicy.single(moduleA);
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Unknown module is denied
    assertThatThrownBy(
            () -> checkFsRead(enforcer, caller("com.unknown.pkg", "com.unknown.module"), dataFile))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("module")
        .hasMessageContaining("com.unknown.module");
  }

  @Test
  @DisplayName("unnamed module uses unnamed policy")
  void unnamedModuleUsesUnnamedPolicy() {
    // Explicit policy for unnamed module (classpath code)
    ModulePolicy unnamedPolicy =
        new ModulePolicy(
            ApplicationPolicy.UNNAMED_MODULE,
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));
    ModulePolicy namedPolicy =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));

    ApplicationPolicy policy = ApplicationPolicy.create(List.of(unnamedPolicy, namedPolicy));
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Unnamed module can read files (its own entitlement)
    assertThatCode(() -> checkFsRead(enforcer, caller("com.classpath.code", "unnamed"), dataFile))
        .doesNotThrowAnyException();

    // Unnamed module cannot create threads (named module's entitlement)
    assertThatThrownBy(
            () ->
                checkOperation(
                    enforcer, caller("com.classpath.code", "unnamed"), Operation.THREAD_CREATE))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("threads.create");
  }

  @Test
  @DisplayName("backward compatibility: single-module policy works for unnamed callers")
  void backwardCompatibilitySingleModuleForUnnamed() {
    // V1-style single module policy (converted to ApplicationPolicy)
    PolicyDescriptor v1Policy =
        PolicyDescriptor.create(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));
    ApplicationPolicy appPolicy = ApplicationPolicy.fromDescriptor(v1Policy);

    PolicyEnforcer enforcer = createEnforcer(appPolicy);

    // Unnamed module callers should work (backward compatibility)
    assertThatCode(() -> checkFsRead(enforcer, caller("com.example.app", "unnamed"), dataFile))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("multiple entitlements per module work correctly")
  void multipleEntitlementsPerModule() {
    ModulePolicy module =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*")),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create")),
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));

    ApplicationPolicy policy = ApplicationPolicy.single(module);
    PolicyEnforcer enforcer = createEnforcer(policy);

    // All entitlements should work
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                checkOperation(
                    enforcer,
                    caller("com.example.app", "com.example.app"),
                    Operation.THREAD_CREATE))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                checkNetworkOutbound(
                    enforcer, caller("com.example.app", "com.example.app"), "example.com", 80))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("package-scoped entitlements work in multi-module context")
  void packageScopedEntitlementsInMultiModule() {
    ModulePolicy module =
        new ModulePolicy(
            "com.example.app",
            List.of(
                new Entitlement(
                    SubjectPattern.exactPackage("com.example.app.io"),
                    fsReadCapability(dataRoot, "*"))));

    ApplicationPolicy policy = ApplicationPolicy.single(module);
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Exact package match in correct module - allowed
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app.io", "com.example.app"), dataFile))
        .doesNotThrowAnyException();

    // Different package in correct module - denied
    assertThatThrownBy(
            () ->
                checkFsRead(enforcer, caller("com.example.app.other", "com.example.app"), dataFile))
        .isInstanceOf(SecurityException.class);

    // Correct package but wrong module - denied
    assertThatThrownBy(
            () -> checkFsRead(enforcer, caller("com.example.app.io", "com.wrong.module"), dataFile))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  @DisplayName("caching works per module")
  void cachingWorksPerModule() {
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.app",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));
    ModulePolicy moduleB =
        new ModulePolicy(
            "com.example.worker",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));

    ApplicationPolicy policy = ApplicationPolicy.create(List.of(moduleA, moduleB));
    PolicyEnforcer enforcer = createEnforcer(policy);

    // First call for module A - should be allowed
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
        .doesNotThrowAnyException();

    // Second call for module A - should hit cache, still allowed
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.app", "com.example.app"), dataFile))
        .doesNotThrowAnyException();

    // Call for module B for same capability - should be denied (different module)
    assertThatThrownBy(
            () ->
                checkFsRead(enforcer, caller("com.example.worker", "com.example.worker"), dataFile))
        .isInstanceOf(SecurityException.class);
  }

  @Test
  @DisplayName("three or more modules work correctly")
  void threeOrMoreModulesWorkCorrectly() {
    ModulePolicy moduleA =
        new ModulePolicy(
            "com.example.core",
            List.of(new Entitlement(SubjectPattern.module(), fsReadCapability(dataRoot, "*"))));
    ModulePolicy moduleB =
        new ModulePolicy(
            "com.example.worker",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("threads.create"))));
    ModulePolicy moduleC =
        new ModulePolicy(
            "com.example.network",
            List.of(
                new Entitlement(SubjectPattern.module(), CapabilityGrant.of("network.outbound"))));

    ApplicationPolicy policy = ApplicationPolicy.create(List.of(moduleA, moduleB, moduleC));
    PolicyEnforcer enforcer = createEnforcer(policy);

    // Each module can use its own capability
    assertThatCode(
            () -> checkFsRead(enforcer, caller("com.example.core", "com.example.core"), dataFile))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                checkOperation(
                    enforcer,
                    caller("com.example.worker", "com.example.worker"),
                    Operation.THREAD_CREATE))
        .doesNotThrowAnyException();
    assertThatCode(
            () ->
                checkNetworkOutbound(
                    enforcer,
                    caller("com.example.network", "com.example.network"),
                    "example.com",
                    80))
        .doesNotThrowAnyException();

    // Each module is denied other modules' capabilities
    assertThatThrownBy(
            () ->
                checkOperation(
                    enforcer,
                    caller("com.example.core", "com.example.core"),
                    Operation.THREAD_CREATE))
        .isInstanceOf(SecurityException.class);
    assertThatThrownBy(
            () ->
                checkNetworkOutbound(
                    enforcer,
                    caller("com.example.worker", "com.example.worker"),
                    "example.com",
                    80))
        .isInstanceOf(SecurityException.class);
    assertThatThrownBy(
            () ->
                checkFsRead(
                    enforcer, caller("com.example.network", "com.example.network"), dataFile))
        .isInstanceOf(SecurityException.class);
  }

  // ===== Helper methods =====

  private CapabilityGrant fsReadCapability(String root, String glob) {
    return CapabilityGrant.of(
        "fs.read",
        List.of(new CapabilityArgument.StringArg(root), new CapabilityArgument.StringArg(glob)));
  }

  private PolicyEnforcer createEnforcer(ApplicationPolicy policy) {
    AgentConfig config =
        new AgentConfig.Builder()
            .policyPath(tempDir.resolve("policy.bin"))
            .mode(EnforcementMode.STRICT)
            .build();
    return new PolicyEnforcer(policy, config);
  }

  private CallerContext caller(String packageName, String moduleName) {
    return new CallerContext(packageName, moduleName);
  }

  private static void checkFsRead(PolicyEnforcer enforcer, CallerContext caller, Path path) {
    SecurityException denial = enforcer.check(caller, Operation.FS_READ, path, 0);
    if (denial != null) {
      throw denial;
    }
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
}
