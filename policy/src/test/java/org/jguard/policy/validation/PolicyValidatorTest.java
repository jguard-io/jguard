/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.validation;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.jguard.policy.ast.Argument;
import org.jguard.policy.ast.Capability;
import org.jguard.policy.ast.EntitlementDeclaration;
import org.jguard.policy.ast.PackagePattern;
import org.jguard.policy.ast.PolicyFile;
import org.jguard.policy.ast.SourceLocation;
import org.jguard.policy.ast.Subject;
import org.jguard.policy.compiler.CompilationResult;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for the policy validator. */
class PolicyValidatorTest {

  private static final SourceLocation LOC = new SourceLocation(1, 1);

  @Nested
  class ModuleNameValidationTest {

    @Test
    void acceptsSimpleModuleName() {
      PolicyFile ast = policyFile(List.of("app"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsDottedModuleName() {
      PolicyFile ast = policyFile(List.of("com", "example", "app"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsModuleNameWithUnderscore() {
      PolicyFile ast = policyFile(List.of("com", "my_app"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsModuleNameWithNumbers() {
      PolicyFile ast = policyFile(List.of("com", "app2"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsModuleNameStartingWithNumber() {
      PolicyFile ast = policyFile(List.of("123app"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Invalid module name"));
    }

    @Test
    void rejectsModuleNameWithJavaKeyword() {
      PolicyFile ast = policyFile(List.of("com", "class", "app"), List.of());
      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Java keyword"));
    }

    @Test
    void rejectsModuleNameWithReservedWord() {
      // Test various Java keywords
      for (String keyword : List.of("public", "private", "static", "void", "null", "true")) {
        PolicyFile ast = policyFile(List.of("com", keyword), List.of());
        PolicyValidator.ValidationResult result = validate(ast);

        assertThat(result.hasErrors()).as("Keyword '%s' should be rejected", keyword).isTrue();
      }
    }
  }

  @Nested
  class PackagePatternValidationTest {

    @Test
    void acceptsValidPackagePattern() {
      EntitlementDeclaration entitlement = entitlement("com.example.net", "network.outbound");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsPackagePatternStartingWithNumber() {
      EntitlementDeclaration entitlement = entitlement("123pkg", "network.outbound");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Invalid package name"));
    }

    @Test
    void rejectsPackagePatternWithJavaKeyword() {
      EntitlementDeclaration entitlement = entitlement("com.import.pkg", "network.outbound");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Java keyword"));
    }
  }

  @Nested
  class CapabilityValidationTest {

    @Test
    void acceptsNetworkOutbound() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.outbound");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkListenWithPort() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.listen", intArg(8080));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsFsReadWithRootAndGlob() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("fs.read", stringArg("/data"), stringArg("*.json"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsFsWriteWithRootAndGlob() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("fs.write", stringArg("/tmp"), stringArg("*.log"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsThreadsSpawn() {
      EntitlementDeclaration entitlement = moduleEntitlement("threads.create");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNativeLoad() {
      EntitlementDeclaration entitlement = moduleEntitlement("native.load");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsUnknownCapability() {
      EntitlementDeclaration entitlement = moduleEntitlement("unknown.capability");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Unknown capability"));
    }

    @Test
    void rejectsCapabilityWithWrongArgumentCount() {
      // fs.read requires 2 arguments, not 1
      EntitlementDeclaration entitlement = moduleEntitlement("fs.read", stringArg("/data"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("requires 2 argument"));
    }

    @Test
    void rejectsCapabilityWithExtraArguments() {
      // network.outbound takes no arguments
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("extra"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("takes no arguments"));
    }

    @Test
    void rejectsCapabilityWithWrongArgumentType() {
      // network.listen requires integer, not string
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.listen", stringArg("not-a-port"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("must be integer"));
    }

    @Test
    void acceptsIdentifierAsStringArgument() {
      // Identifiers should be treated as strings for fs.read
      EntitlementDeclaration entitlement =
          moduleEntitlement("fs.read", identifierArg("ROOT"), identifierArg("GLOB"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }
  }

  @Nested
  class DiagnosticsTest {

    @Test
    void diagnosticIncludesLineAndColumn() {
      SourceLocation errorLoc = new SourceLocation(5, 10);
      Capability capability = new Capability(List.of("unknown"), List.of(), errorLoc);
      Subject subject = new Subject.Module(LOC);
      EntitlementDeclaration entitlement = new EntitlementDeclaration(subject, capability, LOC);
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      CompilationResult.Diagnostic diagnostic = result.diagnostics().get(0);
      assertThat(diagnostic.line()).isEqualTo(5);
      assertThat(diagnostic.column()).isEqualTo(10);
    }

    @Test
    void diagnosticIncludesSourcePath() {
      PolicyFile ast = policyFile(List.of("app"), List.of(moduleEntitlement("unknown.capability")));

      PolicyValidator validator = new PolicyValidator("my-policy.jguard");
      PolicyValidator.ValidationResult result = validator.validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics().get(0).sourcePath()).isEqualTo("my-policy.jguard");
    }

    @Test
    void reportsMultipleErrors() {
      EntitlementDeclaration e1 = moduleEntitlement("unknown.one");
      EntitlementDeclaration e2 = moduleEntitlement("unknown.two");
      PolicyFile ast = policyFile(List.of("123invalid"), List.of(e1, e2));

      PolicyValidator.ValidationResult result = validate(ast);

      // Should report errors for invalid module name and both unknown capabilities
      assertThat(result.diagnostics().size()).isGreaterThanOrEqualTo(2);
    }
  }

  // ===== Helper Methods =====

  private PolicyValidator.ValidationResult validate(PolicyFile ast) {
    PolicyValidator validator = new PolicyValidator("test.jguard");
    return validator.validate(ast);
  }

  private PolicyFile policyFile(
      List<String> moduleName, List<EntitlementDeclaration> entitlements) {
    return new PolicyFile(moduleName, entitlements, LOC);
  }

  private EntitlementDeclaration entitlement(String packageName, String capabilityName) {
    PackagePattern pattern =
        new PackagePattern(List.of(packageName.split("\\.")), PackagePattern.MatchType.EXACT, LOC);
    Subject subject = new Subject.Package(pattern, LOC);
    Capability capability = new Capability(List.of(capabilityName.split("\\.")), List.of(), LOC);
    return new EntitlementDeclaration(subject, capability, LOC);
  }

  private EntitlementDeclaration moduleEntitlement(String capabilityName, Argument... args) {
    Subject subject = new Subject.Module(LOC);
    Capability capability =
        new Capability(List.of(capabilityName.split("\\.")), List.of(args), LOC);
    return new EntitlementDeclaration(subject, capability, LOC);
  }

  private Argument stringArg(String value) {
    return new Argument.StringLiteral(value, LOC);
  }

  private Argument intArg(long value) {
    return new Argument.IntegerLiteral(value, LOC);
  }

  private Argument identifierArg(String value) {
    return new Argument.Identifier(value, LOC);
  }
}
