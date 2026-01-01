/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.lexer;

/**
 * A token produced by the lexer.
 *
 * @param type the token type
 * @param value the token value (text for identifiers/strings, null for punctuation)
 * @param line the 1-based line number
 * @param column the 1-based column number
 */
public record Token(TokenType type, String value, int line, int column) {

  /** Creates a token without a value (for punctuation and keywords). */
  public static Token of(TokenType type, int line, int column) {
    return new Token(type, null, line, column);
  }

  /** Creates a token with a value (for identifiers and literals). */
  public static Token of(TokenType type, String value, int line, int column) {
    return new Token(type, value, line, column);
  }

  @Override
  public String toString() {
    if (value != null) {
      return String.format("%s(%s) at %d:%d", type, value, line, column);
    }
    return String.format("%s at %d:%d", type, line, column);
  }
}
