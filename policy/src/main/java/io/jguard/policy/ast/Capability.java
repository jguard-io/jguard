/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.policy.ast;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A capability in an entitlement declaration.
 *
 * <p>A capability has a dotted name (e.g., "fs.read", "network.outbound") and optional arguments.
 *
 * @param nameSegments the capability name segments (e.g., ["fs", "read"])
 * @param arguments the capability arguments (may be empty)
 * @param location the source location
 */
public record Capability(
    List<String> nameSegments, List<Argument> arguments, SourceLocation location) {

  /** Compact constructor that validates and normalizes the record fields. */
  public Capability {
    Objects.requireNonNull(nameSegments, "nameSegments");
    Objects.requireNonNull(arguments, "arguments");
    Objects.requireNonNull(location, "location");
    nameSegments = List.copyOf(nameSegments);
    arguments = List.copyOf(arguments);
    if (nameSegments.isEmpty()) {
      throw new IllegalArgumentException("Capability must have at least one name segment");
    }
  }

  /**
   * Returns the capability name as a dot-separated string.
   *
   * @return the capability name (e.g., "fs.read")
   */
  public String name() {
    return String.join(".", nameSegments);
  }

  /**
   * Returns true if this capability has arguments.
   *
   * @return true if arguments are present
   */
  public boolean hasArguments() {
    return !arguments.isEmpty();
  }

  @Override
  public String toString() {
    String name = name();
    if (arguments.isEmpty()) {
      return name;
    }
    String args = arguments.stream().map(Argument::toString).collect(Collectors.joining(", "));
    return name + "(" + args + ")";
  }
}
