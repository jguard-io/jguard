/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.model;

import io.jguard.policy.ast.Argument;
import io.jguard.policy.ast.Capability;
import io.jguard.policy.ast.DenyDeclaration;
import io.jguard.policy.ast.EntitlementDeclaration;
import io.jguard.policy.ast.PackagePattern;
import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.ast.Subject;
import java.util.ArrayList;
import java.util.List;

/**
 * Converts a parsed AST into a canonical policy model.
 *
 * <p>This transformation normalizes the policy by sorting entitlements and deduplicating grants.
 * The resulting model is deterministic: identical source files produce byte-identical compiled
 * output.
 */
public final class PolicyBuilder {

  private PolicyBuilder() {
    // Static utility class
  }

  /**
   * Builds a policy descriptor from a parsed policy file AST.
   *
   * @param ast the parsed policy file
   * @return the canonical policy descriptor
   */
  public static PolicyDescriptor build(PolicyFile ast) {
    String moduleName = ast.moduleNameString();
    List<Entitlement> entitlements = new ArrayList<>();
    List<Denial> denials = new ArrayList<>();

    for (EntitlementDeclaration decl : ast.entitlements()) {
      SubjectPattern subject = convertSubject(decl.subject());
      CapabilityGrant capability = convertCapability(decl.capability());
      entitlements.add(new Entitlement(subject, capability));
    }

    for (DenyDeclaration decl : ast.denials()) {
      SubjectPattern subject = convertSubject(decl.subject());
      CapabilityGrant capability = convertCapability(decl.capability());
      denials.add(new Denial(subject, capability, decl.defensive()));
    }

    // PolicyDescriptor constructor handles sorting and deduplication
    return PolicyDescriptor.create(moduleName, entitlements, denials);
  }

  private static SubjectPattern convertSubject(Subject subject) {
    return switch (subject) {
      case Subject.Module m -> SubjectPattern.module();
      case Subject.Package p -> convertPackagePattern(p.pattern());
    };
  }

  private static SubjectPattern convertPackagePattern(PackagePattern pattern) {
    String packageName = pattern.packageName();
    return switch (pattern.matchType()) {
      case EXACT -> SubjectPattern.exactPackage(packageName);
      case DIRECT_SUBPACKAGES -> SubjectPattern.directChildren(packageName);
      case RECURSIVE -> SubjectPattern.recursive(packageName);
    };
  }

  private static CapabilityGrant convertCapability(Capability capability) {
    String name = capability.name();
    List<CapabilityArgument> arguments =
        capability.arguments().stream().map(PolicyBuilder::convertArgument).toList();
    return CapabilityGrant.of(name, arguments);
  }

  private static CapabilityArgument convertArgument(Argument arg) {
    return switch (arg) {
      case Argument.Identifier id -> new CapabilityArgument.StringArg(id.value());
      case Argument.StringLiteral str -> new CapabilityArgument.StringArg(str.value());
      case Argument.IntegerLiteral num -> new CapabilityArgument.IntegerArg(num.value());
    };
  }
}
