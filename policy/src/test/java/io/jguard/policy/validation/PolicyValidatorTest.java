/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.validation;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.policy.ast.Argument;
import io.jguard.policy.ast.Capability;
import io.jguard.policy.ast.DenyDeclaration;
import io.jguard.policy.ast.EntitlementDeclaration;
import io.jguard.policy.ast.PackagePattern;
import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.ast.SourceLocation;
import io.jguard.policy.ast.Subject;
import io.jguard.policy.compiler.CompilationResult;
import java.util.List;
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
      // threads.create takes no arguments
      EntitlementDeclaration entitlement = moduleEntitlement("threads.create", stringArg("extra"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("takes no arguments"));
    }

    @Test
    void rejectsCapabilityWithWrongArgumentType() {
      // fs.read requires strings, not integers
      EntitlementDeclaration entitlement =
          moduleEntitlement("fs.read", intArg(123), stringArg("*.json"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("must be string"));
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

  @Nested
  class NetworkOutboundSemanticValidationTest {

    @Test
    void acceptsNetworkOutboundWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.outbound");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkOutboundWithHostOnly() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*.example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkOutboundWithHostAndPort() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*.example.com"), intArg(443));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkOutboundWithHostAndPortRange() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*.example.com"), stringArg("80-443"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsDoubleStarHostPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("**.example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsStarOnlyPattern() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.outbound", stringArg("*"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsPartialLabelWildcard() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("api*-blue.example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(d -> d.message().contains("Partial-label wildcards not supported"));
    }

    @Test
    void rejectsEmptySegmentInHostPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("api..example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("empty segment"));
    }

    @Test
    void rejectsLeadingDotInHostPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg(".example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("leading/trailing dot"));
    }

    @Test
    void rejectsTrailingDotInHostPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("example.com."));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("leading/trailing dot"));
    }

    @Test
    void rejectsConsecutiveDoubleStars() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("**.**.example.com"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(d -> d.message().contains("Consecutive ** not allowed"));
    }

    @Test
    void rejectsReversedPortRange() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*"), stringArg("443-80"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(d -> d.message().contains("start cannot be greater than end"));
    }

    @Test
    void rejectsPortOutOfRange() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*"), intArg(70000));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("out of range"));
    }

    @Test
    void rejectsInvalidPortSpecFormat() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.outbound", stringArg("*"), stringArg("abc"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Invalid port spec"));
    }
  }

  @Nested
  class EnvAndPropertyValidationTest {

    @Test
    void acceptsEnvReadWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("env.read");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsEnvReadWithPattern() {
      EntitlementDeclaration entitlement = moduleEntitlement("env.read", stringArg("HOME"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsEnvReadWithWildcard() {
      EntitlementDeclaration entitlement = moduleEntitlement("env.read", stringArg("*"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsEnvReadWithEmptyPattern() {
      EntitlementDeclaration entitlement = moduleEntitlement("env.read", stringArg(""));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(d -> d.message().contains("Empty pattern") && d.message().contains("env.read"));
    }

    @Test
    void acceptsSystemPropertyReadWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("system.property.read");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsSystemPropertyReadWithPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("system.property.read", stringArg("java.home"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsSystemPropertyReadWithEmptyPattern() {
      EntitlementDeclaration entitlement = moduleEntitlement("system.property.read", stringArg(""));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(
              d ->
                  d.message().contains("Empty pattern")
                      && d.message().contains("system.property.read"));
    }

    @Test
    void acceptsSystemPropertyWriteWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("system.property.write");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsSystemPropertyWriteWithPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("system.property.write", stringArg("app.config"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsSystemPropertyWriteWithEmptyPattern() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("system.property.write", stringArg(""));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(
              d ->
                  d.message().contains("Empty pattern")
                      && d.message().contains("system.property.write"));
    }

    @Test
    void rejectsNativeLoadWithEmptyPattern() {
      EntitlementDeclaration entitlement = moduleEntitlement("native.load", stringArg(""));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(
              d -> d.message().contains("Empty pattern") && d.message().contains("native.load"));
    }

    @Test
    void rejectsEnvReadWithIntegerArg() {
      // env.read must take a string argument, not integer
      EntitlementDeclaration entitlement = moduleEntitlement("env.read", intArg(123));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("must be string"));
    }

    @Test
    void rejectsEnvReadWithTooManyArgs() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("env.read", stringArg("HOME"), stringArg("extra"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("requires 0 to 1"));
    }
  }

  @Nested
  class NetworkListenSemanticValidationTest {

    @Test
    void acceptsNetworkListenWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.listen");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkListenWithIntegerPort() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.listen", intArg(8080));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsNetworkListenWithPortRange() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.listen", stringArg("8080-8090"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsNetworkListenWithInvalidPortString() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.listen", stringArg("not-a-port"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("Invalid port spec"));
    }

    @Test
    void rejectsNetworkListenWithReversedRange() {
      EntitlementDeclaration entitlement =
          moduleEntitlement("network.listen", stringArg("9000-8000"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(d -> d.message().contains("start cannot be greater than end"));
    }

    @Test
    void rejectsNetworkListenWithPortOutOfRange() {
      EntitlementDeclaration entitlement = moduleEntitlement("network.listen", intArg(70000));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("out of range"));
    }
  }

  @Nested
  class RedundantDenyWarningTest {

    @Test
    void warnsOnRedundantDeny() {
      // Deny a capability that was never granted
      DenyDeclaration denial = moduleDeny("threads.create", false);
      PolicyFile ast = policyFileWithDenials(List.of("app"), List.of(), List.of(denial));

      PolicyValidator.ValidationResult result = validate(ast);

      // Should be valid (no errors) but have a warning
      assertThat(result.isValid()).isTrue();
      assertThat(result.hasWarnings()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(
              d ->
                  d.severity() == CompilationResult.Severity.WARNING
                      && d.message().contains("Redundant deny")
                      && d.message().contains("threads.create"));
    }

    @Test
    void noWarningWhenDenyMatchesGrant() {
      // Grant and then deny the same capability
      EntitlementDeclaration grant = moduleEntitlement("threads.create");
      DenyDeclaration denial = moduleDeny("threads.create", false);
      PolicyFile ast = policyFileWithDenials(List.of("app"), List.of(grant), List.of(denial));

      PolicyValidator.ValidationResult result = validate(ast);

      // Should have no warnings
      assertThat(result.isValid()).isTrue();
      assertThat(result.hasWarnings()).isFalse();
    }

    @Test
    void defensiveDenySuppressesWarning() {
      // Defensive deny should not produce a warning even if capability not granted
      DenyDeclaration denial = moduleDeny("threads.create", true);
      PolicyFile ast = policyFileWithDenials(List.of("app"), List.of(), List.of(denial));

      PolicyValidator.ValidationResult result = validate(ast);

      // Should have no warnings
      assertThat(result.isValid()).isTrue();
      assertThat(result.hasWarnings()).isFalse();
    }

    @Test
    void warningIncludesSubjectInfo() {
      // Test that warning message includes subject pattern
      Subject subject =
          new Subject.Package(
              new PackagePattern(
                  List.of("com", "example"), PackagePattern.MatchType.RECURSIVE, LOC),
              LOC);
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);
      DenyDeclaration denial = new DenyDeclaration(subject, capability, false, LOC);
      PolicyFile ast = policyFileWithDenials(List.of("app"), List.of(), List.of(denial));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasWarnings()).isTrue();
      assertThat(result.diagnostics())
          .anyMatch(
              d -> d.message().contains("com.example..") && d.message().contains("Redundant"));
    }

    @Test
    void multipleRedundantDeniesProduceMultipleWarnings() {
      DenyDeclaration denial1 = moduleDeny("threads.create", false);
      DenyDeclaration denial2 = moduleDeny("native.load", false);
      PolicyFile ast = policyFileWithDenials(List.of("app"), List.of(), List.of(denial1, denial2));

      PolicyValidator.ValidationResult result = validate(ast);

      // Should have two warnings
      long warningCount =
          result.diagnostics().stream()
              .filter(d -> d.severity() == CompilationResult.Severity.WARNING)
              .count();
      assertThat(warningCount).isEqualTo(2);
    }
  }

  // ===== Additional Helper Methods for Denials =====

  private PolicyFile policyFileWithDenials(
      List<String> moduleName,
      List<EntitlementDeclaration> entitlements,
      List<DenyDeclaration> denials) {
    return new PolicyFile(moduleName, entitlements, denials, LOC);
  }

  private DenyDeclaration moduleDeny(String capabilityName, boolean defensive) {
    Subject subject = new Subject.Module(LOC);
    Capability capability = new Capability(List.of(capabilityName.split("\\.")), List.of(), LOC);
    return new DenyDeclaration(subject, capability, defensive, LOC);
  }

  @Nested
  class RuntimeLifecycleValidationTest {

    @Test
    void acceptsRuntimeExitWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("runtime.exit");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsRuntimeExitWithArgs() {
      // runtime.exit takes no arguments
      EntitlementDeclaration entitlement = moduleEntitlement("runtime.exit", intArg(0));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("takes no arguments"));
    }

    @Test
    void acceptsRuntimeShutdownHookWithNoArgs() {
      EntitlementDeclaration entitlement = moduleEntitlement("runtime.shutdown_hook");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void rejectsRuntimeShutdownHookWithArgs() {
      // runtime.shutdown_hook takes no arguments
      EntitlementDeclaration entitlement =
          moduleEntitlement("runtime.shutdown_hook", stringArg("hook"));
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);

      assertThat(result.hasErrors()).isTrue();
      assertThat(result.diagnostics()).anyMatch(d -> d.message().contains("takes no arguments"));
    }

    @Test
    void acceptsRuntimeExitWithPackageSubject() {
      EntitlementDeclaration entitlement = entitlement("com.example.main", "runtime.exit");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }

    @Test
    void acceptsRuntimeShutdownHookWithPackageSubject() {
      EntitlementDeclaration entitlement =
          entitlement("com.example.lifecycle", "runtime.shutdown_hook");
      PolicyFile ast = policyFile(List.of("app"), List.of(entitlement));

      PolicyValidator.ValidationResult result = validate(ast);
      assertThat(result.isValid()).isTrue();
    }
  }
}
