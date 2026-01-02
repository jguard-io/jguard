/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.model;

/**
 * An argument to a capability.
 *
 * <p>Arguments can be strings or integers in the policy model. Identifiers from the AST are
 * converted to strings.
 */
public sealed interface CapabilityArgument
    permits CapabilityArgument.StringArg, CapabilityArgument.IntegerArg {

  /**
   * Returns the canonical string representation for serialization.
   *
   * @return the canonical string
   */
  String toCanonicalString();

  /**
   * A string argument.
   *
   * @param value the string value
   */
  record StringArg(String value) implements CapabilityArgument {
    /** Compact constructor that validates the value is not null. */
    public StringArg {
      if (value == null) {
        throw new IllegalArgumentException("value cannot be null");
      }
    }

    @Override
    public String toCanonicalString() {
      return "\"" + escapeJson(value) + "\"";
    }

    @Override
    public String toString() {
      return toCanonicalString();
    }

    private static String escapeJson(String s) {
      StringBuilder sb = new StringBuilder();
      for (char c : s.toCharArray()) {
        switch (c) {
          case '"' -> sb.append("\\\"");
          case '\\' -> sb.append("\\\\");
          case '\n' -> sb.append("\\n");
          case '\t' -> sb.append("\\t");
          case '\r' -> sb.append("\\r");
          default -> {
            if (c < 32) {
              sb.append(String.format("\\u%04x", (int) c));
            } else {
              sb.append(c);
            }
          }
        }
      }
      return sb.toString();
    }
  }

  /**
   * An integer argument.
   *
   * @param value the integer value
   */
  record IntegerArg(long value) implements CapabilityArgument {
    @Override
    public String toCanonicalString() {
      return Long.toString(value);
    }

    @Override
    public String toString() {
      return toCanonicalString();
    }
  }
}
