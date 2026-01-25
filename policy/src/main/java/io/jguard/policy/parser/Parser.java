/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.parser;

import io.jguard.policy.ast.Argument;
import io.jguard.policy.ast.Capability;
import io.jguard.policy.ast.DenyDeclaration;
import io.jguard.policy.ast.EntitlementDeclaration;
import io.jguard.policy.ast.PackagePattern;
import io.jguard.policy.ast.PolicyFile;
import io.jguard.policy.ast.SourceLocation;
import io.jguard.policy.ast.Subject;
import io.jguard.policy.lexer.Token;
import io.jguard.policy.lexer.TokenType;
import java.util.ArrayList;
import java.util.List;

/**
 * Recursive descent parser for jGuard policy descriptor files.
 *
 * <p>Parses a stream of tokens into an AST.
 */
public final class Parser {

  private final List<Token> tokens;
  private final String sourcePath;
  private final List<ParseError> errors = new ArrayList<>();
  private int current = 0;

  /**
   * Creates a new parser for the given tokens.
   *
   * @param tokens the tokens to parse
   * @param sourcePath the source file path for error reporting
   */
  public Parser(List<Token> tokens, String sourcePath) {
    this.tokens = tokens;
    this.sourcePath = sourcePath;
  }

  /**
   * Parses the tokens and returns the result.
   *
   * @return the parse result containing the AST and any errors
   */
  public ParseResult parse() {
    try {
      PolicyFile policyFile = policyFile();
      return new ParseResult(policyFile, errors);
    } catch (ParseException e) {
      errors.add(new ParseError(e.getMessage(), sourcePath, e.line, e.column));
      return new ParseResult(null, errors);
    }
  }

  // PolicyFile: SecurityModuleDeclaration
  // Keywords are contextual - "security", "module", etc. can appear in package names
  private PolicyFile policyFile() {
    Token securityToken = consumeKeyword("security", "Expected 'security' keyword");
    SourceLocation location = locationOf(securityToken);

    consumeKeyword("module", "Expected 'module' after 'security'");
    List<String> moduleName = dottedName("module name");
    consume(TokenType.LBRACE, "Expected '{' after module name");

    List<EntitlementDeclaration> entitlements = new ArrayList<>();
    List<DenyDeclaration> denials = new ArrayList<>();
    boolean trusted = false;

    while (!check(TokenType.RBRACE) && !isAtEnd()) {
      if (checkKeyword("entitle")) {
        entitlements.add(entitlementDeclaration());
      } else if (checkKeyword("deny")) {
        denials.add(denyDeclaration());
      } else if (checkKeyword("trusted")) {
        advance(); // consume 'trusted'
        consume(TokenType.SEMICOLON, "Expected ';' after 'trusted'");
        trusted = true;
      } else {
        throw error(peek(), "Expected 'entitle', 'deny', or 'trusted'");
      }
    }

    consume(TokenType.RBRACE, "Expected '}' to close security module");

    if (!isAtEnd()) {
      Token extra = peek();
      throw error(extra, "Unexpected content after security module declaration");
    }

    return new PolicyFile(moduleName, entitlements, denials, trusted, location);
  }

  // EntitlementDeclaration: 'entitle' Subject 'to' Capability ';'
  private EntitlementDeclaration entitlementDeclaration() {
    Token entitleToken = consumeKeyword("entitle", "Expected 'entitle'");
    SourceLocation location = locationOf(entitleToken);

    Subject subject = subject();
    consumeKeyword("to", "Expected 'to' after subject");
    Capability capability = capability();
    consume(TokenType.SEMICOLON, "Expected ';' after capability");

    return new EntitlementDeclaration(subject, capability, location);
  }

  // DenyDeclaration: 'deny' ['(' 'defensive' ')'] Subject 'to' Capability ';'
  private DenyDeclaration denyDeclaration() {
    Token denyToken = consumeKeyword("deny", "Expected 'deny'");
    SourceLocation location = locationOf(denyToken);

    // Check for (defensive) modifier
    boolean defensive = false;
    if (match(TokenType.LPAREN)) {
      consumeKeyword("defensive", "Expected 'defensive' after '(' in deny");
      consume(TokenType.RPAREN, "Expected ')' after 'defensive'");
      defensive = true;
    }

    Subject subject = subject();
    consumeKeyword("to", "Expected 'to' after subject");
    Capability capability = capability();
    consume(TokenType.SEMICOLON, "Expected ';' after capability");

    return new DenyDeclaration(subject, capability, defensive, location);
  }

  // Subject: 'module' | PackagePattern
  private Subject subject() {
    if (checkKeyword("module")) {
      Token moduleToken = advance();
      return new Subject.Module(locationOf(moduleToken));
    }
    return new Subject.Package(packagePattern(), locationOf(previous()));
  }

  // PackagePattern: PackageName ('.*' | '..')?
  private PackagePattern packagePattern() {
    Token firstToken = peek();
    List<String> segments = dottedName("package pattern");
    SourceLocation location = locationOf(firstToken);

    PackagePattern.MatchType matchType = PackagePattern.MatchType.EXACT;
    if (match(TokenType.DOT_STAR)) {
      matchType = PackagePattern.MatchType.DIRECT_SUBPACKAGES;
    } else if (match(TokenType.DOT_DOT)) {
      matchType = PackagePattern.MatchType.RECURSIVE;
    }

    return new PackagePattern(segments, matchType, location);
  }

  // Capability: CapabilityName ('(' Arguments? ')')?
  private Capability capability() {
    Token firstToken = peek();
    List<String> nameSegments = dottedName("capability name");
    SourceLocation location = locationOf(firstToken);

    List<Argument> arguments = new ArrayList<>();
    if (match(TokenType.LPAREN)) {
      if (!check(TokenType.RPAREN)) {
        do {
          arguments.add(argument());
        } while (match(TokenType.COMMA));
      }
      consume(TokenType.RPAREN, "Expected ')' after capability arguments");
    }

    return new Capability(nameSegments, arguments, location);
  }

  // Argument: Identifier | StringLiteral | IntegerLiteral
  private Argument argument() {
    if (check(TokenType.IDENTIFIER)) {
      Token token = advance();
      return new Argument.Identifier(token.value(), locationOf(token));
    }
    if (check(TokenType.STRING)) {
      Token token = advance();
      return new Argument.StringLiteral(token.value(), locationOf(token));
    }
    if (check(TokenType.INTEGER)) {
      Token token = advance();
      long value = Long.parseLong(token.value());
      return new Argument.IntegerLiteral(value, locationOf(token));
    }
    throw error(peek(), "Expected argument (identifier, string, or integer)");
  }

  // DottedName: Identifier ('.' Identifier)*
  private List<String> dottedName(String context) {
    List<String> segments = new ArrayList<>();
    Token first = consume(TokenType.IDENTIFIER, "Expected identifier in " + context);
    segments.add(first.value());

    while (match(TokenType.DOT)) {
      // Check for .* or .. which should not be consumed here
      if (check(TokenType.DOT_STAR) || check(TokenType.DOT_DOT)) {
        // Back up - we consumed a DOT but the next is DOT_STAR/DOT_DOT
        // This shouldn't happen with our lexer since .* and .. are single tokens
        break;
      }
      Token segment = consume(TokenType.IDENTIFIER, "Expected identifier after '.' in " + context);
      segments.add(segment.value());
    }

    return segments;
  }

  // Helper methods

  private boolean match(TokenType type) {
    if (check(type)) {
      advance();
      return true;
    }
    return false;
  }

  private boolean check(TokenType type) {
    if (isAtEnd()) return false;
    return peek().type() == type;
  }

  /**
   * Checks if the current token is an identifier with the given keyword value. This enables
   * contextual keywords that can also be used in package/capability names.
   */
  private boolean checkKeyword(String keyword) {
    if (isAtEnd()) return false;
    Token token = peek();
    return token.type() == TokenType.IDENTIFIER && keyword.equals(token.value());
  }

  /**
   * Matches and consumes an identifier with the given keyword value. Returns true if matched, false
   * otherwise.
   */
  private boolean matchKeyword(String keyword) {
    if (checkKeyword(keyword)) {
      advance();
      return true;
    }
    return false;
  }

  /** Consumes an identifier with the given keyword value, or throws an error. */
  private Token consumeKeyword(String keyword, String message) {
    if (checkKeyword(keyword)) return advance();
    throw error(peek(), message);
  }

  private Token advance() {
    if (!isAtEnd()) current++;
    return previous();
  }

  private boolean isAtEnd() {
    return peek().type() == TokenType.EOF;
  }

  private Token peek() {
    return tokens.get(current);
  }

  private Token previous() {
    return tokens.get(current - 1);
  }

  private Token consume(TokenType type, String message) {
    if (check(type)) return advance();
    throw error(peek(), message);
  }

  private ParseException error(Token token, String message) {
    return new ParseException(message, token.line(), token.column());
  }

  private SourceLocation locationOf(Token token) {
    return new SourceLocation(token.line(), token.column());
  }

  @SuppressWarnings("serial") // Never serialized - used only for local control flow
  private static class ParseException extends RuntimeException {
    final int line;
    final int column;

    ParseException(String message, int line, int column) {
      super(message);
      this.line = line;
      this.column = column;
    }
  }

  /**
   * Result of parsing.
   *
   * @param policyFile the parsed policy file, or null if parsing failed
   * @param errors the list of parse errors encountered
   */
  public record ParseResult(PolicyFile policyFile, List<ParseError> errors) {
    /**
     * Returns true if there were any parse errors.
     *
     * @return true if errors exist
     */
    public boolean hasErrors() {
      return !errors.isEmpty();
    }

    /**
     * Returns true if parsing succeeded without errors.
     *
     * @return true if parsing was successful
     */
    public boolean isSuccess() {
      return policyFile != null && errors.isEmpty();
    }
  }

  /**
   * A parse error.
   *
   * @param message the error message
   * @param sourcePath the source file path
   * @param line the 1-based line number
   * @param column the 1-based column number
   */
  public record ParseError(String message, String sourcePath, int line, int column) {
    @Override
    public String toString() {
      return String.format("%s:%d:%d: %s", sourcePath, line, column, message);
    }
  }
}
