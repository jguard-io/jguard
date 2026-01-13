/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.parser;

import static org.assertj.core.api.Assertions.assertThat;

import io.jguard.policy.ast.Argument;
import io.jguard.policy.ast.Capability;
import io.jguard.policy.ast.DenyDeclaration;
import io.jguard.policy.ast.EntitlementDeclaration;
import io.jguard.policy.ast.PackagePattern;
import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.ast.Subject;
import io.jguard.policy.lexer.Lexer;
import io.jguard.policy.lexer.Token;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for the jGuard policy parser. */
class ParserTest {

  // ===== Module Declaration =====

  @Test
  void parsesSimpleModuleName() {
    PolicyFile ast = parse("security module app { }");
    assertThat(ast.moduleName()).containsExactly("app");
    assertThat(ast.moduleNameString()).isEqualTo("app");
  }

  @Test
  void parsesDottedModuleName() {
    PolicyFile ast = parse("security module com.example.app { }");
    assertThat(ast.moduleName()).containsExactly("com", "example", "app");
    assertThat(ast.moduleNameString()).isEqualTo("com.example.app");
  }

  @Test
  void parsesEmptyModule() {
    PolicyFile ast = parse("security module com.example { }");
    assertThat(ast.entitlements()).isEmpty();
  }

  // ===== Entitlement Subjects =====

  @Test
  void parsesModuleSubject() {
    PolicyFile ast = parse("security module app { entitle module to network.outbound; }");
    assertThat(ast.entitlements()).hasSize(1);

    Subject subject = ast.entitlements().get(0).subject();
    assertThat(subject).isInstanceOf(Subject.Module.class);
  }

  @Test
  void parsesExactPackageSubject() {
    PolicyFile ast = parse("security module app { entitle com.example.net to network.outbound; }");
    assertThat(ast.entitlements()).hasSize(1);

    Subject subject = ast.entitlements().get(0).subject();
    assertThat(subject).isInstanceOf(Subject.Package.class);

    Subject.Package pkg = (Subject.Package) subject;
    assertThat(pkg.pattern().packageName()).isEqualTo("com.example.net");
    assertThat(pkg.pattern().matchType()).isEqualTo(PackagePattern.MatchType.EXACT);
  }

  @Test
  void parsesDirectChildrenSubject() {
    PolicyFile ast =
        parse("security module app { entitle com.example.handlers.* to network.outbound; }");
    assertThat(ast.entitlements()).hasSize(1);

    Subject.Package pkg = (Subject.Package) ast.entitlements().get(0).subject();
    assertThat(pkg.pattern().packageName()).isEqualTo("com.example.handlers");
    assertThat(pkg.pattern().matchType()).isEqualTo(PackagePattern.MatchType.DIRECT_SUBPACKAGES);
  }

  @Test
  void parsesRecursiveSubject() {
    PolicyFile ast =
        parse("security module app { entitle com.example.worker.. to threads.create; }");
    assertThat(ast.entitlements()).hasSize(1);

    Subject.Package pkg = (Subject.Package) ast.entitlements().get(0).subject();
    assertThat(pkg.pattern().packageName()).isEqualTo("com.example.worker");
    assertThat(pkg.pattern().matchType()).isEqualTo(PackagePattern.MatchType.RECURSIVE);
  }

  // ===== Capabilities =====

  @Test
  void parsesCapabilityWithoutArguments() {
    PolicyFile ast = parse("security module app { entitle module to network.outbound; }");

    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.name()).isEqualTo("network.outbound");
    assertThat(capability.hasArguments()).isFalse();
    assertThat(capability.arguments()).isEmpty();
  }

  @Test
  void parsesCapabilityWithStringArguments() {
    PolicyFile ast =
        parse("security module app { entitle module to fs.read(\"/data\", \"*.json\"); }");

    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.name()).isEqualTo("fs.read");
    assertThat(capability.hasArguments()).isTrue();
    assertThat(capability.arguments()).hasSize(2);

    Argument.StringLiteral arg1 = (Argument.StringLiteral) capability.arguments().get(0);
    assertThat(arg1.value()).isEqualTo("/data");

    Argument.StringLiteral arg2 = (Argument.StringLiteral) capability.arguments().get(1);
    assertThat(arg2.value()).isEqualTo("*.json");
  }

  @Test
  void parsesCapabilityWithIntegerArgument() {
    PolicyFile ast = parse("security module app { entitle module to network.listen(8080); }");

    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.name()).isEqualTo("network.listen");
    assertThat(capability.arguments()).hasSize(1);

    Argument.IntegerLiteral arg = (Argument.IntegerLiteral) capability.arguments().get(0);
    assertThat(arg.value()).isEqualTo(8080L);
  }

  @Test
  void parsesCapabilityWithIdentifierArgument() {
    PolicyFile ast = parse("security module app { entitle module to fs.read(ROOT, GLOB); }");

    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.arguments()).hasSize(2);

    Argument.Identifier arg1 = (Argument.Identifier) capability.arguments().get(0);
    assertThat(arg1.value()).isEqualTo("ROOT");

    Argument.Identifier arg2 = (Argument.Identifier) capability.arguments().get(1);
    assertThat(arg2.value()).isEqualTo("GLOB");
  }

  @Test
  void parsesCapabilityWithEmptyParens() {
    PolicyFile ast = parse("security module app { entitle module to network.outbound(); }");

    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.name()).isEqualTo("network.outbound");
    assertThat(capability.arguments()).isEmpty();
  }

  // ===== Multiple Entitlements =====

  @Test
  void parsesMultipleEntitlements() {
    String source =
        """
        security module app {
            entitle module to fs.read("/data", "*");
            entitle com.example.net to network.outbound;
            entitle com.example.worker.. to threads.create;
        }
        """;

    PolicyFile ast = parse(source);
    assertThat(ast.entitlements()).hasSize(3);

    // First entitlement
    assertThat(ast.entitlements().get(0).subject()).isInstanceOf(Subject.Module.class);
    assertThat(ast.entitlements().get(0).capability().name()).isEqualTo("fs.read");

    // Second entitlement
    Subject.Package pkg2 = (Subject.Package) ast.entitlements().get(1).subject();
    assertThat(pkg2.pattern().matchType()).isEqualTo(PackagePattern.MatchType.EXACT);
    assertThat(ast.entitlements().get(1).capability().name()).isEqualTo("network.outbound");

    // Third entitlement
    Subject.Package pkg3 = (Subject.Package) ast.entitlements().get(2).subject();
    assertThat(pkg3.pattern().matchType()).isEqualTo(PackagePattern.MatchType.RECURSIVE);
    assertThat(ast.entitlements().get(2).capability().name()).isEqualTo("threads.create");
  }

  // ===== Source Location Tracking =====

  @Test
  void tracksModuleLocation() {
    PolicyFile ast = parse("security module app { }");
    assertThat(ast.location().line()).isEqualTo(1);
    assertThat(ast.location().column()).isEqualTo(1);
  }

  @Test
  void tracksEntitlementLocation() {
    String source =
        """
        security module app {
            entitle module to network.outbound;
        }
        """;

    PolicyFile ast = parse(source);
    EntitlementDeclaration entitlement = ast.entitlements().get(0);
    assertThat(entitlement.location().line()).isEqualTo(2);
  }

  @Test
  void tracksCapabilityLocation() {
    PolicyFile ast = parse("security module app { entitle module to network.outbound; }");
    Capability capability = ast.entitlements().get(0).capability();
    assertThat(capability.location().line()).isEqualTo(1);
  }

  // ===== Comments =====

  @Test
  void handlesLineCommentsBeforeModule() {
    String source =
        """
        // Header comment
        security module app { }
        """;

    PolicyFile ast = parse(source);
    assertThat(ast.moduleNameString()).isEqualTo("app");
  }

  @Test
  void handlesBlockCommentsInModule() {
    String source =
        """
        security module app {
            /* Comment about this entitlement */
            entitle module to network.outbound;
        }
        """;

    PolicyFile ast = parse(source);
    assertThat(ast.entitlements()).hasSize(1);
  }

  @Test
  void handlesLicenseHeader() {
    String source =
        """
        /*
         * SPDX-License-Identifier: Apache-2.0
         */
        security module app {
            entitle module to network.outbound;
        }
        """;

    PolicyFile ast = parse(source);
    assertThat(ast.moduleNameString()).isEqualTo("app");
  }

  // ===== Error Cases =====

  @Test
  void reportsErrorForMissingSecurity() {
    Parser.ParseResult result = parseWithErrors("module app { }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected 'security'");
  }

  @Test
  void reportsErrorForMissingModule() {
    Parser.ParseResult result = parseWithErrors("security app { }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected 'module'");
  }

  @Test
  void reportsErrorForMissingModuleName() {
    Parser.ParseResult result = parseWithErrors("security module { }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected identifier");
  }

  @Test
  void reportsErrorForMissingOpenBrace() {
    Parser.ParseResult result = parseWithErrors("security module app }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected '{'");
  }

  @Test
  void reportsErrorForMissingCloseBrace() {
    Parser.ParseResult result = parseWithErrors("security module app { entitle module to foo;");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected '}'");
  }

  @Test
  void reportsErrorForMissingTo() {
    Parser.ParseResult result =
        parseWithErrors("security module app { entitle module network.outbound; }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected 'to'");
  }

  @Test
  void reportsErrorForMissingSemicolon() {
    Parser.ParseResult result =
        parseWithErrors("security module app { entitle module to network.outbound }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected ';'");
  }

  @Test
  void reportsErrorForMissingCloseParen() {
    Parser.ParseResult result =
        parseWithErrors("security module app { entitle module to fs.read(\"a\"; }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected ')'");
  }

  @Test
  void reportsErrorForExtraContent() {
    Parser.ParseResult result = parseWithErrors("security module app { } extra");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Unexpected content");
  }

  @Test
  void errorIncludesLineAndColumn() {
    String source =
        """
        security module app {
            entitle module network.outbound;
        }
        """;

    Parser.ParseResult result = parseWithErrors(source);
    assertThat(result.hasErrors()).isTrue();
    Parser.ParseError error = result.errors().get(0);
    assertThat(error.line()).isEqualTo(2);
    assertThat(error.sourcePath()).isEqualTo("test.jguard");
  }

  // ===== Deny Declarations =====

  @Test
  void parsesDenyStatement() {
    PolicyFile ast = parse("security module app { deny module to network.outbound; }");
    assertThat(ast.denials()).hasSize(1);

    DenyDeclaration denial = ast.denials().get(0);
    assertThat(denial.subject()).isInstanceOf(Subject.Module.class);
    assertThat(denial.capability().name()).isEqualTo("network.outbound");
    assertThat(denial.defensive()).isFalse();
  }

  @Test
  void parsesDenyDefensiveStatement() {
    PolicyFile ast = parse("security module app { deny(defensive) module to native.load; }");
    assertThat(ast.denials()).hasSize(1);

    DenyDeclaration denial = ast.denials().get(0);
    assertThat(denial.subject()).isInstanceOf(Subject.Module.class);
    assertThat(denial.capability().name()).isEqualTo("native.load");
    assertThat(denial.defensive()).isTrue();
  }

  @Test
  void parsesDenyWithPackageSubject() {
    PolicyFile ast = parse("security module app { deny com.example.app.. to threads.create; }");
    assertThat(ast.denials()).hasSize(1);

    DenyDeclaration denial = ast.denials().get(0);
    Subject.Package pkg = (Subject.Package) denial.subject();
    assertThat(pkg.pattern().packageName()).isEqualTo("com.example.app");
    assertThat(pkg.pattern().matchType()).isEqualTo(PackagePattern.MatchType.RECURSIVE);
  }

  @Test
  void parsesDenyWithCapabilityArguments() {
    PolicyFile ast = parse("security module app { deny module to fs.write(\"/tmp\", \"*.log\"); }");
    assertThat(ast.denials()).hasSize(1);

    DenyDeclaration denial = ast.denials().get(0);
    assertThat(denial.capability().name()).isEqualTo("fs.write");
    assertThat(denial.capability().arguments()).hasSize(2);
  }

  @Test
  void parsesMixedEntitlementsAndDenials() {
    String source =
        """
        security module app {
            entitle module to fs.read("/data", "*.json");
            deny module to network.outbound;
            entitle com.example.net to network.outbound;
            deny(defensive) module to native.load;
        }
        """;

    PolicyFile ast = parse(source);
    assertThat(ast.entitlements()).hasSize(2);
    assertThat(ast.denials()).hasSize(2);

    // Verify denials
    assertThat(ast.denials().get(0).defensive()).isFalse();
    assertThat(ast.denials().get(1).defensive()).isTrue();
  }

  @Test
  void reportsErrorForIncompleteDenyDefensive() {
    Parser.ParseResult result = parseWithErrors("security module app { deny( module to foo; }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected 'defensive'");
  }

  @Test
  void reportsErrorForMissingRightParenInDenyDefensive() {
    Parser.ParseResult result =
        parseWithErrors("security module app { deny(defensive module to foo; }");
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Expected ')'");
  }

  // ===== Helper Methods =====

  private PolicyFile parse(String source) {
    Parser.ParseResult result = parseWithErrors(source);
    assertThat(result.hasErrors()).as("Parse errors: %s", result.errors()).isFalse();
    return result.policyFile();
  }

  private Parser.ParseResult parseWithErrors(String source) {
    Lexer.LexerResult lexerResult = new Lexer(source, "test.jguard").tokenize();
    assertThat(lexerResult.hasErrors()).as("Lexer errors: %s", lexerResult.errors()).isFalse();

    List<Token> tokens = lexerResult.tokens();
    Parser parser = new Parser(tokens, "test.jguard");
    return parser.parse();
  }
}
