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
  SECURITY, // 'security'
  MODULE, // 'module'
  ENTITLE, // 'entitle'
  TO, // 'to'

  // Literals
  IDENTIFIER, // e.g., 'org', 'jguard', 'fs'
  STRING, // e.g., "/tmp"
  INTEGER, // e.g., 8080

  // Punctuation
  LBRACE, // '{'
  RBRACE, // '}'
  LPAREN, // '('
  RPAREN, // ')'
  SEMICOLON, // ';'
  COMMA, // ','
  DOT, // '.'

  // Special patterns
  DOT_STAR, // '.*' (direct subpackages)
  DOT_DOT, // '..' (recursive subpackages)

  // End of file
  EOF
}
