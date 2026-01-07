/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.compiler;

import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.lexer.Lexer;
import io.jguard.policy.model.PolicyBuilder;
import io.jguard.policy.model.PolicyDescriptor;
import io.jguard.policy.parser.Parser;
import io.jguard.policy.serialization.BinaryPolicyWriter;
import io.jguard.policy.serialization.JsonPolicyWriter;
import io.jguard.policy.validation.PolicyValidator;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Compiles jGuard policy descriptors ({@code module-info.jguard}) into binary and optional JSON
 * formats.
 *
 * <p>This is the main entry point for policy compilation, used by both the Gradle plugin and CLI.
 *
 * <p>Compilation phases:
 *
 * <ol>
 *   <li>Lexical analysis (tokenization)
 *   <li>Parsing (AST construction)
 *   <li>Validation (well-formedness checks)
 *   <li>Model building (canonical policy model)
 *   <li>Serialization (binary and/or JSON)
 * </ol>
 */
public final class PolicyCompiler {

  private PolicyCompiler() {
    // Static utility class
  }

  /**
   * Compiles a policy descriptor file into binary format and optionally JSON.
   *
   * @param source the path to the {@code module-info.jguard} source file
   * @param binOutput the path where the binary policy file will be written
   * @param jsonOutput the path where the JSON policy file will be written, or {@code null} to skip
   *     JSON
   * @return the compilation result indicating success or failure with diagnostics
   * @throws IOException if an I/O error occurs during compilation
   */
  public static CompilationResult compile(Path source, Path binOutput, Path jsonOutput)
      throws IOException {
    String sourcePath = source.toString();

    // Read source file
    if (!Files.exists(source)) {
      return CompilationResult.failure(
          CompilationResult.Diagnostic.error("Source file does not exist: " + source));
    }
    String sourceText = Files.readString(source);

    // Compile to policy descriptor
    CompileResult result = compileSource(sourceText, sourcePath);
    if (result.hasErrors()) {
      return CompilationResult.failure(result.diagnostics());
    }

    PolicyDescriptor policy = result.policy();

    // Ensure output directories exist
    Files.createDirectories(binOutput.getParent());

    // Write binary output
    try (OutputStream out = Files.newOutputStream(binOutput)) {
      BinaryPolicyWriter.write(policy, out);
    }

    // Write JSON output if requested
    if (jsonOutput != null) {
      Files.createDirectories(jsonOutput.getParent());
      String json = JsonPolicyWriter.toJson(policy);
      Files.writeString(jsonOutput, json);
    }

    return CompilationResult.success();
  }

  /**
   * Compiles source text to a policy descriptor.
   *
   * @param sourceText the source text
   * @param sourcePath the source path (for error reporting)
   * @return the compile result
   */
  public static CompileResult compileSource(String sourceText, String sourcePath) {
    List<CompilationResult.Diagnostic> diagnostics = new ArrayList<>();

    // Phase 1: Lexical analysis
    Lexer lexer = new Lexer(sourceText, sourcePath);
    Lexer.LexerResult lexerResult = lexer.tokenize();

    if (lexerResult.hasErrors()) {
      for (Lexer.LexerError error : lexerResult.errors()) {
        diagnostics.add(
            CompilationResult.Diagnostic.error(
                error.message(), error.sourcePath(), error.line(), error.column()));
      }
      return new CompileResult(null, diagnostics);
    }

    // Phase 2: Parsing
    Parser parser = new Parser(lexerResult.tokens(), sourcePath);
    Parser.ParseResult parseResult = parser.parse();

    if (parseResult.hasErrors()) {
      for (Parser.ParseError error : parseResult.errors()) {
        diagnostics.add(
            CompilationResult.Diagnostic.error(
                error.message(), error.sourcePath(), error.line(), error.column()));
      }
      return new CompileResult(null, diagnostics);
    }

    PolicyFile ast = parseResult.policyFile();

    // Phase 3: Validation
    PolicyValidator validator = new PolicyValidator(sourcePath);
    PolicyValidator.ValidationResult validationResult = validator.validate(ast);

    if (validationResult.hasErrors()) {
      diagnostics.addAll(validationResult.diagnostics());
      return new CompileResult(null, diagnostics);
    }

    // Phase 4: Model building
    PolicyDescriptor policy = PolicyBuilder.build(ast);

    return new CompileResult(policy, diagnostics);
  }

  /**
   * Result of compiling source text to a policy descriptor.
   *
   * @param policy the compiled policy, or null if compilation failed
   * @param diagnostics the list of compilation diagnostics
   */
  public record CompileResult(
      PolicyDescriptor policy, List<CompilationResult.Diagnostic> diagnostics) {
    /**
     * Returns true if there were any compilation errors.
     *
     * @return true if errors exist
     */
    public boolean hasErrors() {
      return policy == null
          || diagnostics.stream().anyMatch(d -> d.severity() == CompilationResult.Severity.ERROR);
    }

    /**
     * Returns true if compilation succeeded without errors.
     *
     * @return true if compilation was successful
     */
    public boolean isSuccess() {
      return policy != null && !hasErrors();
    }
  }
}
