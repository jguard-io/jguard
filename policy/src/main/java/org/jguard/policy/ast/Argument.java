/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.ast;

/**
 * An argument to a capability.
 *
 * <p>Arguments can be identifiers, strings, or integers.
 */
public sealed interface Argument
    permits Argument.Identifier, Argument.StringLiteral, Argument.IntegerLiteral {

  /** Returns the source location of this argument. */
  SourceLocation location();

  /** An identifier argument. */
  record Identifier(String value, SourceLocation location) implements Argument {
    @Override
    public String toString() {
      return value;
    }
  }

  /** A string literal argument. */
  record StringLiteral(String value, SourceLocation location) implements Argument {
    @Override
    public String toString() {
      return "\"" + escapeString(value) + "\"";
    }

    private static String escapeString(String s) {
      StringBuilder sb = new StringBuilder();
      for (char c : s.toCharArray()) {
        switch (c) {
          case '"' -> sb.append("\\\"");
          case '\\' -> sb.append("\\\\");
          case '\n' -> sb.append("\\n");
          case '\t' -> sb.append("\\t");
          case '\r' -> sb.append("\\r");
          default -> sb.append(c);
        }
      }
      return sb.toString();
    }
  }

  /** An integer literal argument. */
  record IntegerLiteral(long value, SourceLocation location) implements Argument {
    @Override
    public String toString() {
      return Long.toString(value);
    }
  }
}
