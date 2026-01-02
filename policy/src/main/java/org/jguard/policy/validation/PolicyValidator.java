/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.jguard.policy.ast.Argument;
import org.jguard.policy.ast.Capability;
import org.jguard.policy.ast.EntitlementDeclaration;
import org.jguard.policy.ast.PackagePattern;
import org.jguard.policy.ast.PolicyFile;
import org.jguard.policy.ast.SourceLocation;
import org.jguard.policy.ast.Subject;
import org.jguard.policy.compiler.CompilationResult;

/**
 * Validates a parsed policy AST against well-formedness rules.
 *
 * <p>Checks include:
 *
 * <ul>
 *   <li>Module name validity
 *   <li>Package pattern validity
 *   <li>Capability name recognition
 *   <li>Capability argument validation
 * </ul>
 */
public final class PolicyValidator {

  // Valid Java identifier pattern for module/package segments
  private static final Pattern JAVA_IDENTIFIER = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");

  // Known capabilities and their expected argument counts
  // For v0.1.0: fs.read(root, glob) and network.outbound
  private static final Map<String, CapabilitySignature> KNOWN_CAPABILITIES =
      Map.of(
          "fs.read", new CapabilitySignature(2, 2, List.of(ArgType.STRING, ArgType.STRING)),
          "fs.write", new CapabilitySignature(2, 2, List.of(ArgType.STRING, ArgType.STRING)),
          "network.outbound", new CapabilitySignature(0, 0, List.of()),
          "network.listen", new CapabilitySignature(0, 1, List.of(ArgType.INTEGER)),
          "threads.spawn", new CapabilitySignature(0, 0, List.of()),
          "native.load", new CapabilitySignature(0, 0, List.of()));

  private final String sourcePath;
  private final List<CompilationResult.Diagnostic> diagnostics = new ArrayList<>();

  /**
   * Creates a new policy validator for the given source path.
   *
   * @param sourcePath the source file path for error reporting
   */
  public PolicyValidator(String sourcePath) {
    this.sourcePath = sourcePath;
  }

  /**
   * Validates a policy file AST.
   *
   * @param ast the parsed policy file
   * @return the validation result with any diagnostics
   */
  public ValidationResult validate(PolicyFile ast) {
    validateModuleName(ast.moduleName(), ast.location());

    for (EntitlementDeclaration entitlement : ast.entitlements()) {
      validateEntitlement(entitlement);
    }

    return new ValidationResult(diagnostics);
  }

  private void validateModuleName(List<String> segments, SourceLocation location) {
    if (segments.isEmpty()) {
      error("Module name cannot be empty", location);
      return;
    }

    for (String segment : segments) {
      if (!isValidJavaIdentifier(segment)) {
        error("Invalid module name segment: '" + segment + "'", location);
      }
      if (isJavaKeyword(segment)) {
        error("Module name segment cannot be a Java keyword: '" + segment + "'", location);
      }
    }
  }

  private void validateEntitlement(EntitlementDeclaration entitlement) {
    validateSubject(entitlement.subject());
    validateCapability(entitlement.capability());
  }

  private void validateSubject(Subject subject) {
    switch (subject) {
      case Subject.Module m -> {
        // Module subject is always valid
      }
      case Subject.Package p -> validatePackagePattern(p.pattern());
    }
  }

  private void validatePackagePattern(PackagePattern pattern) {
    if (pattern.segments().isEmpty()) {
      error("Package pattern cannot be empty", pattern.location());
      return;
    }

    for (String segment : pattern.segments()) {
      if (!isValidJavaIdentifier(segment)) {
        error("Invalid package name segment: '" + segment + "'", pattern.location());
      }
      if (isJavaKeyword(segment)) {
        error(
            "Package name segment cannot be a Java keyword: '" + segment + "'", pattern.location());
      }
    }
  }

  private void validateCapability(Capability capability) {
    String name = capability.name();
    SourceLocation location = capability.location();

    // Check if capability is known
    CapabilitySignature signature = KNOWN_CAPABILITIES.get(name);
    if (signature == null) {
      error("Unknown capability: '" + name + "'", location);
      return;
    }

    // Check argument count
    int minCount = signature.minArgCount();
    int maxCount = signature.maxArgCount();
    int actualCount = capability.arguments().size();

    if (actualCount < minCount || actualCount > maxCount) {
      if (minCount == maxCount) {
        // Fixed argument count
        if (minCount == 0) {
          error(
              "Capability '" + name + "' takes no arguments, but " + actualCount + " provided",
              location);
        } else {
          error(
              "Capability '"
                  + name
                  + "' requires "
                  + minCount
                  + " argument(s), but "
                  + actualCount
                  + " provided",
              location);
        }
      } else {
        // Variable argument count
        error(
            "Capability '"
                + name
                + "' requires "
                + minCount
                + " to "
                + maxCount
                + " argument(s), but "
                + actualCount
                + " provided",
            location);
      }
      return;
    }

    // Check argument types (only for provided arguments)
    List<Argument> args = capability.arguments();
    for (int i = 0; i < args.size(); i++) {
      Argument arg = args.get(i);
      ArgType expectedType = signature.argTypes().get(i);
      validateArgument(arg, expectedType, name, i);
    }
  }

  private void validateArgument(
      Argument arg, ArgType expectedType, String capabilityName, int index) {
    boolean valid =
        switch (expectedType) {
          case STRING ->
              arg instanceof Argument.StringLiteral || arg instanceof Argument.Identifier;
          case INTEGER -> arg instanceof Argument.IntegerLiteral;
        };

    if (!valid) {
      String actualType =
          switch (arg) {
            case Argument.Identifier i -> "identifier";
            case Argument.StringLiteral s -> "string";
            case Argument.IntegerLiteral n -> "integer";
          };
      error(
          "Capability '"
              + capabilityName
              + "' argument "
              + (index + 1)
              + " must be "
              + expectedType.name().toLowerCase()
              + ", got "
              + actualType,
          arg.location());
    }
  }

  private void error(String message, SourceLocation location) {
    diagnostics.add(
        CompilationResult.Diagnostic.error(
            message, sourcePath, location.line(), location.column()));
  }

  private static boolean isValidJavaIdentifier(String s) {
    return s != null && !s.isEmpty() && JAVA_IDENTIFIER.matcher(s).matches();
  }

  private static final Set<String> JAVA_KEYWORDS =
      Set.of(
          "abstract",
          "assert",
          "boolean",
          "break",
          "byte",
          "case",
          "catch",
          "char",
          "class",
          "const",
          "continue",
          "default",
          "do",
          "double",
          "else",
          "enum",
          "extends",
          "final",
          "finally",
          "float",
          "for",
          "goto",
          "if",
          "implements",
          "import",
          "instanceof",
          "int",
          "interface",
          "long",
          "native",
          "new",
          "package",
          "private",
          "protected",
          "public",
          "return",
          "short",
          "static",
          "strictfp",
          "super",
          "switch",
          "synchronized",
          "this",
          "throw",
          "throws",
          "transient",
          "try",
          "void",
          "volatile",
          "while",
          "true",
          "false",
          "null",
          "_");

  private static boolean isJavaKeyword(String s) {
    return JAVA_KEYWORDS.contains(s);
  }

  private record CapabilitySignature(int minArgCount, int maxArgCount, List<ArgType> argTypes) {}

  private enum ArgType {
    STRING,
    INTEGER
  }

  /**
   * Result of validation.
   *
   * @param diagnostics the validation diagnostics
   */
  public record ValidationResult(List<CompilationResult.Diagnostic> diagnostics) {
    /**
     * Returns true if there were any validation errors.
     *
     * @return true if errors exist
     */
    public boolean hasErrors() {
      return diagnostics.stream().anyMatch(d -> d.severity() == CompilationResult.Severity.ERROR);
    }

    /**
     * Returns true if validation succeeded without errors.
     *
     * @return true if validation was successful
     */
    public boolean isValid() {
      return !hasErrors();
    }
  }
}
