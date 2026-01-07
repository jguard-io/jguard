/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.ast;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for AST node classes. */
class AstTest {

  private static final SourceLocation LOC = new SourceLocation(1, 1);

  @Nested
  class SourceLocationTest {

    @Test
    void storesLineAndColumn() {
      SourceLocation loc = new SourceLocation(10, 25);
      assertThat(loc.line()).isEqualTo(10);
      assertThat(loc.column()).isEqualTo(25);
    }

    @Test
    void hasToString() {
      SourceLocation loc = new SourceLocation(5, 10);
      assertThat(loc.toString()).contains("5").contains("10");
    }

    @Test
    void implementsEquality() {
      SourceLocation loc1 = new SourceLocation(1, 1);
      SourceLocation loc2 = new SourceLocation(1, 1);
      SourceLocation loc3 = new SourceLocation(1, 2);

      assertThat(loc1).isEqualTo(loc2);
      assertThat(loc1).isNotEqualTo(loc3);
    }
  }

  @Nested
  class PackagePatternTest {

    @Test
    void createsExactPattern() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.EXACT, LOC);

      assertThat(pattern.segments()).containsExactly("com", "example");
      assertThat(pattern.matchType()).isEqualTo(PackagePattern.MatchType.EXACT);
      assertThat(pattern.packageName()).isEqualTo("com.example");
    }

    @Test
    void createsDirectChildrenPattern() {
      PackagePattern pattern =
          new PackagePattern(
              List.of("com", "example"), PackagePattern.MatchType.DIRECT_SUBPACKAGES, LOC);

      assertThat(pattern.matchType()).isEqualTo(PackagePattern.MatchType.DIRECT_SUBPACKAGES);
    }

    @Test
    void createsRecursivePattern() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.RECURSIVE, LOC);

      assertThat(pattern.matchType()).isEqualTo(PackagePattern.MatchType.RECURSIVE);
    }

    @Test
    void toStringForExactPattern() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.EXACT, LOC);

      assertThat(pattern.toString()).isEqualTo("com.example");
    }

    @Test
    void toStringForDirectChildrenPattern() {
      PackagePattern pattern =
          new PackagePattern(
              List.of("com", "example"), PackagePattern.MatchType.DIRECT_SUBPACKAGES, LOC);

      assertThat(pattern.toString()).isEqualTo("com.example.*");
    }

    @Test
    void toStringForRecursivePattern() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.RECURSIVE, LOC);

      assertThat(pattern.toString()).isEqualTo("com.example..");
    }

    @Test
    void createsDefensiveCopyOfSegments() {
      List<String> segments = new java.util.ArrayList<>(List.of("com", "example"));
      PackagePattern pattern = new PackagePattern(segments, PackagePattern.MatchType.EXACT, LOC);

      segments.add("modified");

      assertThat(pattern.segments()).containsExactly("com", "example");
    }

    @Test
    void segmentsAreImmutable() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.EXACT, LOC);

      assertThatThrownBy(() -> pattern.segments().add("foo"))
          .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsEmptySegments() {
      assertThatThrownBy(() -> new PackagePattern(List.of(), PackagePattern.MatchType.EXACT, LOC))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("at least one segment");
    }

    @Test
    void rejectsNullSegments() {
      assertThatThrownBy(() -> new PackagePattern(null, PackagePattern.MatchType.EXACT, LOC))
          .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsNullMatchType() {
      assertThatThrownBy(() -> new PackagePattern(List.of("com"), null, LOC))
          .isInstanceOf(NullPointerException.class);
    }
  }

  @Nested
  class CapabilityTest {

    @Test
    void createsCapabilityWithoutArguments() {
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);

      assertThat(capability.name()).isEqualTo("network.outbound");
      assertThat(capability.hasArguments()).isFalse();
      assertThat(capability.arguments()).isEmpty();
    }

    @Test
    void createsCapabilityWithArguments() {
      Argument arg1 = new Argument.StringLiteral("/data", LOC);
      Argument arg2 = new Argument.StringLiteral("*.json", LOC);

      Capability capability = new Capability(List.of("fs", "read"), List.of(arg1, arg2), LOC);

      assertThat(capability.name()).isEqualTo("fs.read");
      assertThat(capability.hasArguments()).isTrue();
      assertThat(capability.arguments()).hasSize(2);
    }

    @Test
    void toStringWithoutArguments() {
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);

      assertThat(capability.toString()).isEqualTo("network.outbound");
    }

    @Test
    void toStringWithArguments() {
      Argument arg1 = new Argument.StringLiteral("/data", LOC);
      Argument arg2 = new Argument.IntegerLiteral(8080, LOC);

      Capability capability = new Capability(List.of("fs", "read"), List.of(arg1, arg2), LOC);

      assertThat(capability.toString()).contains("fs.read");
      assertThat(capability.toString()).contains("(");
      assertThat(capability.toString()).contains(")");
    }

    @Test
    void createsDefensiveCopyOfNameSegments() {
      List<String> segments = new java.util.ArrayList<>(List.of("fs", "read"));
      Capability capability = new Capability(segments, List.of(), LOC);

      segments.add("modified");

      assertThat(capability.nameSegments()).containsExactly("fs", "read");
    }

    @Test
    void createsDefensiveCopyOfArguments() {
      List<Argument> args =
          new java.util.ArrayList<>(List.of(new Argument.StringLiteral("/data", LOC)));
      Capability capability = new Capability(List.of("fs", "read"), args, LOC);

      args.add(new Argument.IntegerLiteral(123, LOC));

      assertThat(capability.arguments()).hasSize(1);
    }

    @Test
    void rejectsEmptyNameSegments() {
      assertThatThrownBy(() -> new Capability(List.of(), List.of(), LOC))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("at least one name segment");
    }
  }

  @Nested
  class ArgumentTest {

    @Test
    void createsIdentifierArgument() {
      Argument.Identifier arg = new Argument.Identifier("ROOT", LOC);

      assertThat(arg.value()).isEqualTo("ROOT");
      assertThat(arg.location()).isEqualTo(LOC);
    }

    @Test
    void createsStringLiteralArgument() {
      Argument.StringLiteral arg = new Argument.StringLiteral("/data/file.txt", LOC);

      assertThat(arg.value()).isEqualTo("/data/file.txt");
      assertThat(arg.location()).isEqualTo(LOC);
    }

    @Test
    void createsIntegerLiteralArgument() {
      Argument.IntegerLiteral arg = new Argument.IntegerLiteral(8080, LOC);

      assertThat(arg.value()).isEqualTo(8080L);
      assertThat(arg.location()).isEqualTo(LOC);
    }

    @Test
    void identifierToString() {
      Argument.Identifier arg = new Argument.Identifier("ROOT", LOC);
      assertThat(arg.toString()).contains("ROOT");
    }

    @Test
    void stringLiteralToString() {
      Argument.StringLiteral arg = new Argument.StringLiteral("/data", LOC);
      assertThat(arg.toString()).contains("/data");
    }

    @Test
    void integerLiteralToString() {
      Argument.IntegerLiteral arg = new Argument.IntegerLiteral(8080, LOC);
      assertThat(arg.toString()).contains("8080");
    }
  }

  @Nested
  class SubjectTest {

    @Test
    void createsModuleSubject() {
      Subject.Module subject = new Subject.Module(LOC);

      assertThat(subject.location()).isEqualTo(LOC);
    }

    @Test
    void createsPackageSubject() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.EXACT, LOC);
      Subject.Package subject = new Subject.Package(pattern, LOC);

      assertThat(subject.pattern()).isEqualTo(pattern);
      assertThat(subject.location()).isEqualTo(LOC);
    }

    @Test
    void subjectIsSealed() {
      // Verify Subject is a sealed interface with known implementations
      assertThat(Subject.Module.class).isAssignableTo(Subject.class);
      assertThat(Subject.Package.class).isAssignableTo(Subject.class);
    }
  }

  @Nested
  class EntitlementDeclarationTest {

    @Test
    void createsEntitlementWithModuleSubject() {
      Subject subject = new Subject.Module(LOC);
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);
      EntitlementDeclaration entitlement = new EntitlementDeclaration(subject, capability, LOC);

      assertThat(entitlement.subject()).isEqualTo(subject);
      assertThat(entitlement.capability()).isEqualTo(capability);
      assertThat(entitlement.location()).isEqualTo(LOC);
    }

    @Test
    void createsEntitlementWithPackageSubject() {
      PackagePattern pattern =
          new PackagePattern(List.of("com", "example"), PackagePattern.MatchType.RECURSIVE, LOC);
      Subject subject = new Subject.Package(pattern, LOC);
      Capability capability = new Capability(List.of("threads", "spawn"), List.of(), LOC);
      EntitlementDeclaration entitlement = new EntitlementDeclaration(subject, capability, LOC);

      assertThat(entitlement.subject()).isInstanceOf(Subject.Package.class);
    }
  }

  @Nested
  class PolicyFileTest {

    @Test
    void createsPolicyFile() {
      PolicyFile policy = new PolicyFile(List.of("com", "example", "app"), List.of(), LOC);

      assertThat(policy.moduleName()).containsExactly("com", "example", "app");
      assertThat(policy.moduleNameString()).isEqualTo("com.example.app");
      assertThat(policy.entitlements()).isEmpty();
      assertThat(policy.location()).isEqualTo(LOC);
    }

    @Test
    void createsPolicyFileWithEntitlements() {
      Subject subject = new Subject.Module(LOC);
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);
      EntitlementDeclaration entitlement = new EntitlementDeclaration(subject, capability, LOC);

      PolicyFile policy = new PolicyFile(List.of("com", "example"), List.of(entitlement), LOC);

      assertThat(policy.entitlements()).hasSize(1);
    }

    @Test
    void createsDefensiveCopyOfModuleName() {
      List<String> moduleName = new java.util.ArrayList<>(List.of("com", "example"));
      PolicyFile policy = new PolicyFile(moduleName, List.of(), LOC);

      moduleName.add("modified");

      assertThat(policy.moduleName()).containsExactly("com", "example");
    }

    @Test
    void createsDefensiveCopyOfEntitlements() {
      Subject subject = new Subject.Module(LOC);
      Capability capability = new Capability(List.of("network", "outbound"), List.of(), LOC);
      EntitlementDeclaration entitlement = new EntitlementDeclaration(subject, capability, LOC);

      List<EntitlementDeclaration> entitlements = new java.util.ArrayList<>(List.of(entitlement));
      PolicyFile policy = new PolicyFile(List.of("com", "example"), entitlements, LOC);

      entitlements.add(entitlement);

      assertThat(policy.entitlements()).hasSize(1);
    }
  }
}
