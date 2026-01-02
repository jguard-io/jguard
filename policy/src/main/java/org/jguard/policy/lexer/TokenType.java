/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.lexer;

/** Token types for the jGuard policy descriptor language. */
public enum TokenType {
  // Keywords

  /** The 'security' keyword. */
  SECURITY,

  /** The 'module' keyword. */
  MODULE,

  /** The 'entitle' keyword. */
  ENTITLE,

  /** The 'to' keyword. */
  TO,

  // Literals

  /** An identifier (e.g., 'org', 'jguard', 'fs'). */
  IDENTIFIER,

  /** A string literal (e.g., "/tmp"). */
  STRING,

  /** An integer literal (e.g., 8080). */
  INTEGER,

  // Punctuation

  /** Left brace '{'. */
  LBRACE,

  /** Right brace '}'. */
  RBRACE,

  /** Left parenthesis '('. */
  LPAREN,

  /** Right parenthesis ')'. */
  RPAREN,

  /** Semicolon ';'. */
  SEMICOLON,

  /** Comma ','. */
  COMMA,

  /** Dot '.'. */
  DOT,

  // Special patterns

  /** Dot-star '.*' (direct subpackages). */
  DOT_STAR,

  /** Dot-dot '..' (recursive subpackages). */
  DOT_DOT,

  // End of file

  /** End of file marker. */
  EOF
}
