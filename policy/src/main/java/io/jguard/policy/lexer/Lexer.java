/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.lexer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Lexer for jGuard policy descriptor files.
 *
 * <p>Tokenizes {@code module-info.jguard} source text into a stream of tokens.
 */
public final class Lexer {

  // All keywords are contextual - they are valid as identifiers in package/capability names.
  // The parser checks identifier values in positions where keywords are expected.
  // This allows package names like "com.example.security" or "com.example.module.to".
  private static final Map<String, TokenType> KEYWORDS = Map.of();

  private final String source;
  private final String sourcePath;
  private final List<Token> tokens = new ArrayList<>();
  private final List<LexerError> errors = new ArrayList<>();

  private int start = 0;
  private int current = 0;
  private int line = 1;
  private int column = 1;
  private int tokenStartColumn = 1;

  /**
   * Creates a new lexer for the given source text.
   *
   * @param source the source text to tokenize
   * @param sourcePath the source file path for error reporting
   */
  public Lexer(String source, String sourcePath) {
    this.source = source;
    this.sourcePath = sourcePath;
  }

  /**
   * Tokenizes the source and returns the result.
   *
   * @return the lexer result containing tokens and any errors
   */
  public LexerResult tokenize() {
    while (!isAtEnd()) {
      start = current;
      tokenStartColumn = column;
      scanToken();
    }
    tokens.add(Token.of(TokenType.EOF, line, column));
    return new LexerResult(tokens, errors);
  }

  private void scanToken() {
    char c = advance();
    switch (c) {
      case '{' -> addToken(TokenType.LBRACE);
      case '}' -> addToken(TokenType.RBRACE);
      case '(' -> addToken(TokenType.LPAREN);
      case ')' -> addToken(TokenType.RPAREN);
      case ';' -> addToken(TokenType.SEMICOLON);
      case ',' -> addToken(TokenType.COMMA);
      case '.' -> {
        if (match('.')) {
          addToken(TokenType.DOT_DOT);
        } else if (match('*')) {
          addToken(TokenType.DOT_STAR);
        } else {
          addToken(TokenType.DOT);
        }
      }
      case '/' -> {
        if (match('/')) {
          lineComment();
        } else if (match('*')) {
          blockComment();
        } else {
          error("Unexpected character: /");
        }
      }
      case '"' -> string();
      case ' ', '\r', '\t' -> {
        // Ignore whitespace
      }
      case '\n' -> {
        line++;
        column = 1;
      }
      default -> {
        if (isDigit(c)) {
          number();
        } else if (isAlpha(c)) {
          identifier();
        } else {
          error("Unexpected character: " + c);
        }
      }
    }
  }

  private void lineComment() {
    while (peek() != '\n' && !isAtEnd()) {
      advance();
    }
  }

  private void blockComment() {
    int startLine = line;
    int startCol = tokenStartColumn;

    while (!isAtEnd()) {
      if (peek() == '*' && peekNext() == '/') {
        advance(); // consume '*'
        advance(); // consume '/'
        return;
      }
      if (peek() == '\n') {
        line++;
        column = 0; // will be incremented by advance()
      }
      advance();
    }
    errors.add(new LexerError("Unterminated block comment", sourcePath, startLine, startCol));
  }

  private void string() {
    int startLine = line;
    int startCol = tokenStartColumn;
    StringBuilder value = new StringBuilder();

    while (peek() != '"' && !isAtEnd()) {
      if (peek() == '\n') {
        errors.add(
            new LexerError(
                "Unterminated string (newline in string)", sourcePath, startLine, startCol));
        return;
      }
      if (peek() == '\\') {
        advance(); // consume backslash
        if (isAtEnd()) {
          errors.add(new LexerError("Unterminated escape sequence", sourcePath, line, column));
          return;
        }
        char escaped = advance();
        switch (escaped) {
          case '"' -> value.append('"');
          case '\\' -> value.append('\\');
          case 'n' -> value.append('\n');
          case 't' -> value.append('\t');
          case 'r' -> value.append('\r');
          case 'u' -> {
            if (current + 4 > source.length()) {
              errors.add(new LexerError("Incomplete unicode escape", sourcePath, line, column));
              return;
            }
            String hex = source.substring(current, current + 4);
            try {
              int codePoint = Integer.parseInt(hex, 16);
              value.append((char) codePoint);
              current += 4;
              column += 4;
            } catch (NumberFormatException e) {
              errors.add(
                  new LexerError("Invalid unicode escape: \\u" + hex, sourcePath, line, column));
              return;
            }
          }
          default -> {
            errors.add(
                new LexerError("Invalid escape sequence: \\" + escaped, sourcePath, line, column));
            return;
          }
        }
      } else {
        value.append(advance());
      }
    }

    if (isAtEnd()) {
      errors.add(new LexerError("Unterminated string", sourcePath, startLine, startCol));
      return;
    }

    advance(); // consume closing quote
    addToken(TokenType.STRING, value.toString());
  }

  private void number() {
    while (isDigit(peek())) {
      advance();
    }
    String value = source.substring(start, current);
    addToken(TokenType.INTEGER, value);
  }

  private void identifier() {
    while (isAlphaNumeric(peek())) {
      advance();
    }
    String text = source.substring(start, current);
    TokenType type = KEYWORDS.getOrDefault(text, TokenType.IDENTIFIER);
    if (type == TokenType.IDENTIFIER) {
      addToken(type, text);
    } else {
      addToken(type);
    }
  }

  private boolean isAtEnd() {
    return current >= source.length();
  }

  private char advance() {
    char c = source.charAt(current);
    current++;
    column++;
    return c;
  }

  private char peek() {
    if (isAtEnd()) return '\0';
    return source.charAt(current);
  }

  private char peekNext() {
    if (current + 1 >= source.length()) return '\0';
    return source.charAt(current + 1);
  }

  private boolean match(char expected) {
    if (isAtEnd()) return false;
    if (source.charAt(current) != expected) return false;
    current++;
    column++;
    return true;
  }

  private void addToken(TokenType type) {
    tokens.add(Token.of(type, line, tokenStartColumn));
  }

  private void addToken(TokenType type, String value) {
    tokens.add(Token.of(type, value, line, tokenStartColumn));
  }

  private void error(String message) {
    errors.add(new LexerError(message, sourcePath, line, tokenStartColumn));
  }

  private static boolean isDigit(char c) {
    return c >= '0' && c <= '9';
  }

  private static boolean isAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
  }

  private static boolean isAlphaNumeric(char c) {
    return isAlpha(c) || isDigit(c);
  }

  /**
   * Result of lexical analysis.
   *
   * @param tokens the tokens produced by lexical analysis
   * @param errors the errors encountered during lexical analysis
   */
  public record LexerResult(List<Token> tokens, List<LexerError> errors) {
    /**
     * Returns true if there were any lexical errors.
     *
     * @return true if errors exist
     */
    public boolean hasErrors() {
      return !errors.isEmpty();
    }
  }

  /**
   * A lexical error.
   *
   * @param message the error message
   * @param sourcePath the source file path
   * @param line the 1-based line number where the error occurred
   * @param column the 1-based column number where the error occurred
   */
  public record LexerError(String message, String sourcePath, int line, int column) {
    @Override
    public String toString() {
      return String.format("%s:%d:%d: %s", sourcePath, line, column, message);
    }
  }
}
