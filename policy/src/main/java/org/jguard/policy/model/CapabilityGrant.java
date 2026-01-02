/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.policy.model;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A capability grant in an entitlement.
 *
 * <p>A capability grant specifies what operation is permitted, with optional arguments that
 * constrain the grant.
 *
 * @param name the capability name (e.g., "fs.read", "network.outbound")
 * @param arguments the capability arguments (may be empty)
 */
public record CapabilityGrant(String name, List<CapabilityArgument> arguments)
    implements Comparable<CapabilityGrant> {

  private static final Comparator<CapabilityGrant> COMPARATOR =
      Comparator.comparing(CapabilityGrant::name).thenComparing(CapabilityGrant::argumentsString);

  /** Compact constructor that validates and normalizes the record fields. */
  public CapabilityGrant {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(arguments, "arguments");
    if (name.isEmpty()) {
      throw new IllegalArgumentException("Capability name cannot be empty");
    }
    arguments = List.copyOf(arguments);
  }

  /**
   * Creates a capability grant with no arguments.
   *
   * @param name the capability name
   * @return the capability grant
   */
  public static CapabilityGrant of(String name) {
    return new CapabilityGrant(name, List.of());
  }

  /**
   * Creates a capability grant with the specified arguments.
   *
   * @param name the capability name
   * @param arguments the capability arguments
   * @return the capability grant
   */
  public static CapabilityGrant of(String name, List<CapabilityArgument> arguments) {
    return new CapabilityGrant(name, arguments);
  }

  /**
   * Returns true if this capability has arguments.
   *
   * @return true if arguments are present
   */
  public boolean hasArguments() {
    return !arguments.isEmpty();
  }

  /**
   * Returns the canonical string representation for serialization.
   *
   * @return the canonical string
   */
  public String toCanonicalString() {
    if (arguments.isEmpty()) {
      return name;
    }
    String args =
        arguments.stream()
            .map(CapabilityArgument::toCanonicalString)
            .collect(Collectors.joining(", "));
    return name + "(" + args + ")";
  }

  private String argumentsString() {
    return arguments.stream()
        .map(CapabilityArgument::toCanonicalString)
        .collect(Collectors.joining(","));
  }

  @Override
  public int compareTo(CapabilityGrant other) {
    return COMPARATOR.compare(this, other);
  }

  @Override
  public String toString() {
    return toCanonicalString();
  }
}
