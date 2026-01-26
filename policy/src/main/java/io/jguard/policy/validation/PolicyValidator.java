/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.validation;

import io.jguard.policy.ast.Argument;
import io.jguard.policy.ast.Capability;
import io.jguard.policy.ast.DenyDeclaration;
import io.jguard.policy.ast.EntitlementDeclaration;
import io.jguard.policy.ast.PackagePattern;
import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.ast.SourceLocation;
import io.jguard.policy.ast.Subject;
import io.jguard.policy.compiler.CompilationResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

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
  // Capabilities: fs.read/write/hardlink, network.outbound/listen, threads.create, native.load,
  // env.read, system.property.read/write, process.exec, crypto.provider, runtime.exit/shutdown_hook
  private static final Map<String, CapabilitySignature> KNOWN_CAPABILITIES =
      Map.ofEntries(
          Map.entry(
              "fs.read", new CapabilitySignature(2, 2, List.of(ArgType.STRING, ArgType.STRING))),
          Map.entry(
              "fs.write", new CapabilitySignature(2, 2, List.of(ArgType.STRING, ArgType.STRING))),
          Map.entry(
              "fs.hardlink",
              new CapabilitySignature(2, 2, List.of(ArgType.STRING, ArgType.STRING))),
          Map.entry(
              "network.outbound",
              new CapabilitySignature(0, 2, List.of(ArgType.STRING, ArgType.STRING_OR_INTEGER))),
          Map.entry(
              "network.listen", new CapabilitySignature(0, 1, List.of(ArgType.STRING_OR_INTEGER))),
          Map.entry("threads.create", new CapabilitySignature(0, 0, List.of())),
          Map.entry("native.load", new CapabilitySignature(0, 1, List.of(ArgType.STRING))),
          Map.entry("env.read", new CapabilitySignature(0, 1, List.of(ArgType.STRING))),
          Map.entry("system.property.read", new CapabilitySignature(0, 1, List.of(ArgType.STRING))),
          Map.entry(
              "system.property.write", new CapabilitySignature(0, 1, List.of(ArgType.STRING))),
          Map.entry("process.exec", new CapabilitySignature(0, 1, List.of(ArgType.STRING))),
          Map.entry("crypto.provider", new CapabilitySignature(0, 0, List.of())),
          Map.entry("runtime.exit", new CapabilitySignature(0, 0, List.of())),
          Map.entry("runtime.shutdown_hook", new CapabilitySignature(0, 0, List.of())));

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

    for (DenyDeclaration denial : ast.denials()) {
      validateDenial(denial, ast.entitlements());
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

  private void validateDenial(DenyDeclaration denial, List<EntitlementDeclaration> entitlements) {
    validateSubject(denial.subject());
    validateCapability(denial.capability());

    // Check for redundant denies - warn if denial doesn't match any grant
    // Skip if denial is marked as defensive
    if (!denial.defensive()) {
      String denyCapability = denial.capability().name();
      boolean matchesAnyGrant =
          entitlements.stream().anyMatch(e -> e.capability().name().equals(denyCapability));

      if (!matchesAnyGrant) {
        warning(
            "Redundant deny: '"
                + formatSubject(denial.subject())
                + "' -> "
                + denyCapability
                + " (not in granted set). Use 'deny(defensive)' to suppress",
            denial.capability().location());
      }
    }
  }

  private String formatSubject(Subject subject) {
    return switch (subject) {
      case Subject.Module m -> "module";
      case Subject.Package p -> formatPackagePattern(p.pattern());
    };
  }

  private String formatPackagePattern(PackagePattern pattern) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.join(".", pattern.segments()));
    switch (pattern.matchType()) {
      case EXACT -> {}
      case RECURSIVE -> sb.append("..");
      case DIRECT_SUBPACKAGES -> sb.append(".*");
    }
    return sb.toString();
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

    // Semantic validation per capability
    validateCapabilitySemantics(name, args, location);
  }

  private void validateCapabilitySemantics(
      String name, List<Argument> args, SourceLocation location) {
    switch (name) {
      case "network.outbound" -> validateNetworkOutbound(args, location);
      case "network.listen" -> validateNetworkListen(args, location);
      case "env.read" -> validateTargetPattern(name, args, location);
      case "system.property.read" -> validateTargetPattern(name, args, location);
      case "system.property.write" -> validateTargetPattern(name, args, location);
      case "native.load" -> validateTargetPattern(name, args, location);
      case "process.exec" -> validateTargetPattern(name, args, location);
      default -> {
        // Other capabilities don't need semantic validation yet
      }
    }
  }

  private void validateNetworkOutbound(List<Argument> args, SourceLocation location) {
    if (args.isEmpty()) {
      return; // OK: any host, any port
    }

    // First arg must be host pattern (string)
    Argument firstArg = args.get(0);
    if (firstArg instanceof Argument.StringLiteral s) {
      validateHostPattern(s.value(), location);
    } else if (firstArg instanceof Argument.Identifier id) {
      validateHostPattern(id.value(), location);
    }
    // IntegerLiteral for first arg is a type error already caught above

    // Second arg (if present) must be port spec
    if (args.size() >= 2) {
      validatePortSpec(args.get(1), location);
    }
  }

  private void validateNetworkListen(List<Argument> args, SourceLocation location) {
    if (args.isEmpty()) {
      return; // OK: any port
    }
    validatePortSpec(args.get(0), location);
  }

  /**
   * Validates a target pattern for capabilities like env.read, system.property.read/write,
   * native.load.
   *
   * <p>Empty patterns are rejected to prevent accidental policy bypass. Use no-arg or "*" for "any
   * target".
   */
  private void validateTargetPattern(
      String capabilityName, List<Argument> args, SourceLocation location) {
    if (args.isEmpty()) {
      return; // OK: any target (no-arg)
    }

    Argument arg = args.get(0);
    String pattern = null;
    if (arg instanceof Argument.StringLiteral s) {
      pattern = s.value();
    } else if (arg instanceof Argument.Identifier id) {
      pattern = id.value();
    }

    if (pattern != null && pattern.isEmpty()) {
      error(
          "Empty pattern for '"
              + capabilityName
              + "' is not allowed. Use no arguments or \"*\" for any target",
          location);
    }
  }

  private void validateHostPattern(String pattern, SourceLocation location) {
    if (pattern == null || pattern.isEmpty()) {
      error("Host pattern cannot be empty", location);
      return;
    }

    // Reject trailing/leading dots in policy
    if (pattern.startsWith(".") || pattern.endsWith(".")) {
      error("Invalid host pattern (leading/trailing dot): " + pattern, location);
      return;
    }

    // Validate segment-by-segment
    String[] segments = pattern.split("\\.");
    for (int i = 0; i < segments.length; i++) {
      String seg = segments[i];

      if (seg.isEmpty()) {
        error("Invalid host pattern (empty segment): " + pattern, location);
        return;
      }

      // Each segment must be: "*", "**", or literal with no wildcards
      if (seg.contains("*")) {
        if (!seg.equals("*") && !seg.equals("**")) {
          error("Partial-label wildcards not supported: " + pattern, location);
          return;
        }
        // Reject consecutive ** segments
        if (seg.equals("**") && i > 0 && segments[i - 1].equals("**")) {
          error("Consecutive ** not allowed: " + pattern, location);
          return;
        }
      }
    }
  }

  private void validatePortSpec(Argument arg, SourceLocation location) {
    if (arg instanceof Argument.IntegerLiteral intArg) {
      long port = intArg.value();
      if (port < 0 || port > 65535) {
        error("Port out of range (0-65535): " + port, location);
      }
    } else if (arg instanceof Argument.StringLiteral strArg) {
      String spec = strArg.value().trim();
      if (!spec.matches("\\d+(-\\d+)?")) {
        error("Invalid port spec (expected 'port' or 'start-end'): " + spec, location);
        return;
      }
      // Parse and validate range
      int dashIndex = spec.indexOf('-');
      if (dashIndex == -1) {
        // Single port
        long port = Long.parseLong(spec);
        if (port < 0 || port > 65535) {
          error("Port out of range (0-65535): " + port, location);
        }
      } else {
        // Range
        long start = Long.parseLong(spec.substring(0, dashIndex));
        long end = Long.parseLong(spec.substring(dashIndex + 1));
        if (start < 0 || start > 65535) {
          error("Start port out of range (0-65535): " + start, location);
        }
        if (end < 0 || end > 65535) {
          error("End port out of range (0-65535): " + end, location);
        }
        if (start > end) {
          error("Port range start cannot be greater than end: " + spec, location);
        }
      }
    } else if (arg instanceof Argument.Identifier id) {
      // Identifiers for port specs are allowed (e.g., named constants)
      // We can't validate the value at compile time
    }
  }

  private void validateArgument(
      Argument arg, ArgType expectedType, String capabilityName, int index) {
    boolean valid =
        switch (expectedType) {
          case STRING ->
              arg instanceof Argument.StringLiteral || arg instanceof Argument.Identifier;
          case INTEGER -> arg instanceof Argument.IntegerLiteral;
          case STRING_OR_INTEGER ->
              arg instanceof Argument.StringLiteral
                  || arg instanceof Argument.Identifier
                  || arg instanceof Argument.IntegerLiteral;
        };

    if (!valid) {
      String actualType =
          switch (arg) {
            case Argument.Identifier i -> "identifier";
            case Argument.StringLiteral s -> "string";
            case Argument.IntegerLiteral n -> "integer";
          };
      String expectedDescription =
          expectedType == ArgType.STRING_OR_INTEGER
              ? "string or integer"
              : expectedType.name().toLowerCase();
      error(
          "Capability '"
              + capabilityName
              + "' argument "
              + (index + 1)
              + " must be "
              + expectedDescription
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

  private void warning(String message, SourceLocation location) {
    diagnostics.add(
        new CompilationResult.Diagnostic(
            CompilationResult.Severity.WARNING,
            message,
            sourcePath,
            location.line(),
            location.column()));
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
    INTEGER,
    STRING_OR_INTEGER
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
     * Returns true if there were any validation warnings.
     *
     * @return true if warnings exist
     */
    public boolean hasWarnings() {
      return diagnostics.stream().anyMatch(d -> d.severity() == CompilationResult.Severity.WARNING);
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
