/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.lexer;

/**
 * Token types for the jGuard policy descriptor language.
 *
 * <p>Note: All keywords (security, module, entitle, deny, to, trusted, defensive) are contextual -
 * they tokenize as IDENTIFIER and the parser checks their values in context. This allows package
 * names like "com.example.security" or "com.example.module.to".
 */
public enum TokenType {
  // Literals

  /** An identifier (e.g., 'org', 'jguard', 'fs', and contextual keywords). */
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
