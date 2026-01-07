/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.ast;

/**
 * Source location for AST nodes, used for error reporting.
 *
 * @param line the 1-based line number
 * @param column the 1-based column number
 */
public record SourceLocation(int line, int column) {

  @Override
  public String toString() {
    return line + ":" + column;
  }
}
