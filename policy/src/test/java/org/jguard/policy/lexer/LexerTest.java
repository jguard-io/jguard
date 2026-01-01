/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.lexer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Comprehensive tests for the jGuard policy lexer. */
class LexerTest {

  // ===== Keywords =====

  @Test
  void tokenizesSecurityKeyword() {
    List<Token> tokens = tokenize("security");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.SECURITY);
  }

  @Test
  void tokenizesModuleKeyword() {
    List<Token> tokens = tokenize("module");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.MODULE);
  }

  @Test
  void tokenizesEntitleKeyword() {
    List<Token> tokens = tokenize("entitle");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.ENTITLE);
  }

  @Test
  void tokenizesToKeyword() {
    List<Token> tokens = tokenize("to");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.TO);
  }

  @Test
  void tokenizesAllKeywordsInSequence() {
    List<Token> tokens = tokenize("security module entitle to");
    assertThat(tokens).hasSize(5);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.SECURITY);
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.MODULE);
    assertThat(tokens.get(2).type()).isEqualTo(TokenType.ENTITLE);
    assertThat(tokens.get(3).type()).isEqualTo(TokenType.TO);
    assertThat(tokens.get(4).type()).isEqualTo(TokenType.EOF);
  }

  // ===== Identifiers =====

  @Test
  void tokenizesSimpleIdentifier() {
    List<Token> tokens = tokenize("foo");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
  }

  @Test
  void tokenizesIdentifierWithNumbers() {
    List<Token> tokens = tokenize("foo123");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("foo123");
  }

  @Test
  void tokenizesIdentifierWithUnderscore() {
    List<Token> tokens = tokenize("foo_bar");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("foo_bar");
  }

  @Test
  void tokenizesIdentifierStartingWithUnderscore() {
    List<Token> tokens = tokenize("_private");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("_private");
  }

  @Test
  void tokenizesUppercaseIdentifier() {
    List<Token> tokens = tokenize("CONSTANT");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("CONSTANT");
  }

  @Test
  void tokenizesMixedCaseIdentifier() {
    List<Token> tokens = tokenize("CamelCase");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("CamelCase");
  }

  // ===== Strings =====

  @Test
  void tokenizesSimpleString() {
    List<Token> tokens = tokenize("\"hello\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("hello");
  }

  @Test
  void tokenizesEmptyString() {
    List<Token> tokens = tokenize("\"\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("");
  }

  @Test
  void tokenizesStringWithSpaces() {
    List<Token> tokens = tokenize("\"hello world\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("hello world");
  }

  @Test
  void tokenizesStringWithEscapedQuote() {
    List<Token> tokens = tokenize("\"say \\\"hi\\\"\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("say \"hi\"");
  }

  @Test
  void tokenizesStringWithEscapedBackslash() {
    List<Token> tokens = tokenize("\"path\\\\to\\\\file\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("path\\to\\file");
  }

  @Test
  void tokenizesStringWithEscapedNewline() {
    List<Token> tokens = tokenize("\"line1\\nline2\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("line1\nline2");
  }

  @Test
  void tokenizesStringWithEscapedTab() {
    List<Token> tokens = tokenize("\"col1\\tcol2\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("col1\tcol2");
  }

  @Test
  void tokenizesStringWithEscapedCarriageReturn() {
    List<Token> tokens = tokenize("\"line\\r\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("line\r");
  }

  @Test
  void tokenizesStringWithUnicodeEscape() {
    List<Token> tokens = tokenize("\"\\u0041\""); // 'A'
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("A");
  }

  @Test
  void tokenizesStringWithGlobPattern() {
    List<Token> tokens = tokenize("\"**/*.json\"");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(0).value()).isEqualTo("**/*.json");
  }

  // ===== Integers =====

  @Test
  void tokenizesSingleDigit() {
    List<Token> tokens = tokenize("5");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.INTEGER);
    assertThat(tokens.get(0).value()).isEqualTo("5");
  }

  @Test
  void tokenizesMultiDigitNumber() {
    List<Token> tokens = tokenize("8080");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.INTEGER);
    assertThat(tokens.get(0).value()).isEqualTo("8080");
  }

  @Test
  void tokenizesZero() {
    List<Token> tokens = tokenize("0");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.INTEGER);
    assertThat(tokens.get(0).value()).isEqualTo("0");
  }

  // ===== Punctuation =====

  @Test
  void tokenizesLeftBrace() {
    List<Token> tokens = tokenize("{");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.LBRACE);
  }

  @Test
  void tokenizesRightBrace() {
    List<Token> tokens = tokenize("}");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.RBRACE);
  }

  @Test
  void tokenizesLeftParen() {
    List<Token> tokens = tokenize("(");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.LPAREN);
  }

  @Test
  void tokenizesRightParen() {
    List<Token> tokens = tokenize(")");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.RPAREN);
  }

  @Test
  void tokenizesSemicolon() {
    List<Token> tokens = tokenize(";");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.SEMICOLON);
  }

  @Test
  void tokenizesComma() {
    List<Token> tokens = tokenize(",");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.COMMA);
  }

  @Test
  void tokenizesDot() {
    List<Token> tokens = tokenize(".");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.DOT);
  }

  @Test
  void tokenizesDotStar() {
    List<Token> tokens = tokenize(".*");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.DOT_STAR);
  }

  @Test
  void tokenizesDotDot() {
    List<Token> tokens = tokenize("..");
    assertThat(tokens).hasSize(2);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.DOT_DOT);
  }

  // ===== Comments =====

  @Test
  void skipsLineComment() {
    List<Token> tokens = tokenize("foo // this is a comment\nbar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(1).value()).isEqualTo("bar");
  }

  @Test
  void skipsBlockComment() {
    List<Token> tokens = tokenize("foo /* comment */ bar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(1).value()).isEqualTo("bar");
  }

  @Test
  void skipsMultiLineBlockComment() {
    List<Token> tokens = tokenize("foo /* line1\nline2\nline3 */ bar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.IDENTIFIER);
  }

  @Test
  void skipsJavadocStyleComment() {
    List<Token> tokens = tokenize("foo /** javadoc */ bar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.IDENTIFIER);
  }

  // ===== Whitespace =====

  @Test
  void skipsSpaces() {
    List<Token> tokens = tokenize("foo   bar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
    assertThat(tokens.get(1).value()).isEqualTo("bar");
  }

  @Test
  void skipsTabs() {
    List<Token> tokens = tokenize("foo\t\tbar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
    assertThat(tokens.get(1).value()).isEqualTo("bar");
  }

  @Test
  void skipsCarriageReturns() {
    List<Token> tokens = tokenize("foo\r\nbar");
    assertThat(tokens).hasSize(3);
    assertThat(tokens.get(0).value()).isEqualTo("foo");
    assertThat(tokens.get(1).value()).isEqualTo("bar");
  }

  // ===== Line and Column Tracking =====

  @Test
  void tracksColumnForFirstToken() {
    List<Token> tokens = tokenize("foo");
    assertThat(tokens.get(0).line()).isEqualTo(1);
    assertThat(tokens.get(0).column()).isEqualTo(1);
  }

  @Test
  void tracksColumnAfterSpaces() {
    List<Token> tokens = tokenize("   foo");
    assertThat(tokens.get(0).line()).isEqualTo(1);
    assertThat(tokens.get(0).column()).isEqualTo(4);
  }

  @Test
  void tracksLineAfterNewline() {
    List<Token> tokens = tokenize("foo\nbar");
    assertThat(tokens.get(0).line()).isEqualTo(1);
    assertThat(tokens.get(1).line()).isEqualTo(2);
    assertThat(tokens.get(1).column()).isEqualTo(1);
  }

  @Test
  void tracksMultipleLines() {
    List<Token> tokens = tokenize("a\nb\nc");
    assertThat(tokens.get(0).line()).isEqualTo(1);
    assertThat(tokens.get(1).line()).isEqualTo(2);
    assertThat(tokens.get(2).line()).isEqualTo(3);
  }

  // ===== Error Cases =====

  @Test
  void reportsUnterminatedString() {
    Lexer.LexerResult result = new Lexer("\"unterminated", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Unterminated string");
  }

  @Test
  void reportsNewlineInString() {
    Lexer.LexerResult result = new Lexer("\"line1\nline2\"", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("newline in string");
  }

  @Test
  void reportsInvalidEscapeSequence() {
    Lexer.LexerResult result = new Lexer("\"\\x\"", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Invalid escape sequence");
  }

  @Test
  void reportsIncompleteUnicodeEscape() {
    Lexer.LexerResult result = new Lexer("\"\\u00\"", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Incomplete unicode escape");
  }

  @Test
  void reportsInvalidUnicodeEscape() {
    Lexer.LexerResult result = new Lexer("\"\\uGGGG\"", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Invalid unicode escape");
  }

  @Test
  void reportsUnterminatedBlockComment() {
    Lexer.LexerResult result = new Lexer("/* unterminated", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Unterminated block comment");
  }

  @Test
  void reportsUnexpectedCharacter() {
    Lexer.LexerResult result = new Lexer("@", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Unexpected character");
  }

  @Test
  void reportsSlashWithoutComment() {
    Lexer.LexerResult result = new Lexer("/", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    assertThat(result.errors().get(0).message()).contains("Unexpected character: /");
  }

  @Test
  void errorIncludesLineAndColumn() {
    Lexer.LexerResult result = new Lexer("foo\n  @", "test.jguard").tokenize();
    assertThat(result.hasErrors()).isTrue();
    Lexer.LexerError error = result.errors().get(0);
    assertThat(error.line()).isEqualTo(2);
    assertThat(error.column()).isEqualTo(3);
  }

  // ===== Complete Policy Tokenization =====

  @Test
  void tokenizesCompletePolicy() {
    String source =
        """
        security module com.example.app {
            entitle module to fs.read("/data", "*.json");
        }
        """;

    List<Token> tokens = tokenize(source);

    // security module com.example.app {
    assertThat(tokens.get(0).type()).isEqualTo(TokenType.SECURITY);
    assertThat(tokens.get(1).type()).isEqualTo(TokenType.MODULE);
    assertThat(tokens.get(2).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(2).value()).isEqualTo("com");
    assertThat(tokens.get(3).type()).isEqualTo(TokenType.DOT);
    assertThat(tokens.get(4).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(4).value()).isEqualTo("example");
    assertThat(tokens.get(5).type()).isEqualTo(TokenType.DOT);
    assertThat(tokens.get(6).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(6).value()).isEqualTo("app");
    assertThat(tokens.get(7).type()).isEqualTo(TokenType.LBRACE);

    // entitle module to fs.read("/data", "*.json");
    assertThat(tokens.get(8).type()).isEqualTo(TokenType.ENTITLE);
    assertThat(tokens.get(9).type()).isEqualTo(TokenType.MODULE);
    assertThat(tokens.get(10).type()).isEqualTo(TokenType.TO);
    assertThat(tokens.get(11).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(11).value()).isEqualTo("fs");
    assertThat(tokens.get(12).type()).isEqualTo(TokenType.DOT);
    assertThat(tokens.get(13).type()).isEqualTo(TokenType.IDENTIFIER);
    assertThat(tokens.get(13).value()).isEqualTo("read");
    assertThat(tokens.get(14).type()).isEqualTo(TokenType.LPAREN);
    assertThat(tokens.get(15).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(15).value()).isEqualTo("/data");
    assertThat(tokens.get(16).type()).isEqualTo(TokenType.COMMA);
    assertThat(tokens.get(17).type()).isEqualTo(TokenType.STRING);
    assertThat(tokens.get(17).value()).isEqualTo("*.json");
    assertThat(tokens.get(18).type()).isEqualTo(TokenType.RPAREN);
    assertThat(tokens.get(19).type()).isEqualTo(TokenType.SEMICOLON);

    // }
    assertThat(tokens.get(20).type()).isEqualTo(TokenType.RBRACE);
    assertThat(tokens.get(21).type()).isEqualTo(TokenType.EOF);
  }

  // ===== Helper Methods =====

  private List<Token> tokenize(String source) {
    Lexer.LexerResult result = new Lexer(source, "test.jguard").tokenize();
    assertThat(result.hasErrors()).as("Lexer errors: %s", result.errors()).isFalse();
    return result.tokens();
  }
}
