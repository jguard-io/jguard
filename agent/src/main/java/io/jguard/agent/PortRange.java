/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

/**
 * Represents a port or port range for network capability matching.
 *
 * <p>Supports both single ports and ranges:
 *
 * <ul>
 *   <li>{@code "8080"} - single port
 *   <li>{@code "80-443"} - port range (inclusive)
 * </ul>
 *
 * @param start the start port (inclusive)
 * @param end the end port (inclusive)
 */
public record PortRange(int start, int end) {

  private static final int MIN_PORT = 0;
  private static final int MAX_PORT = 65535;

  /**
   * Creates a PortRange with validation.
   *
   * @throws IllegalArgumentException if ports are out of range or start > end
   */
  public PortRange {
    if (start < MIN_PORT || start > MAX_PORT) {
      throw new IllegalArgumentException("Start port out of range (0-65535): " + start);
    }
    if (end < MIN_PORT || end > MAX_PORT) {
      throw new IllegalArgumentException("End port out of range (0-65535): " + end);
    }
    if (start > end) {
      throw new IllegalArgumentException(
          "Start port cannot be greater than end port: " + start + "-" + end);
    }
  }

  /**
   * Parses a port specification string.
   *
   * @param spec port spec like "8080" or "80-443"
   * @return the parsed PortRange
   * @throws IllegalArgumentException if spec is invalid
   */
  public static PortRange parse(String spec) {
    if (spec == null || spec.isEmpty()) {
      throw new IllegalArgumentException("Port spec cannot be null or empty");
    }

    String trimmed = spec.trim();
    if (!trimmed.equals(spec)) {
      throw new IllegalArgumentException(
          "Port spec cannot have leading/trailing whitespace: '" + spec + "'");
    }

    int dashIndex = spec.indexOf('-');
    if (dashIndex == -1) {
      // Single port
      int port = parsePort(spec);
      return new PortRange(port, port);
    }

    // Range: split on dash
    if (dashIndex == 0) {
      throw new IllegalArgumentException("Invalid port spec (starts with dash): " + spec);
    }
    if (dashIndex == spec.length() - 1) {
      throw new IllegalArgumentException("Invalid port spec (ends with dash): " + spec);
    }

    String startStr = spec.substring(0, dashIndex);
    String endStr = spec.substring(dashIndex + 1);

    int start = parsePort(startStr);
    int end = parsePort(endStr);

    return new PortRange(start, end);
  }

  private static int parsePort(String s) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Invalid port number: " + s);
    }
  }

  /**
   * Creates a PortRange for a single port.
   *
   * @param port the port number
   * @return a PortRange representing exactly this port
   */
  public static PortRange single(int port) {
    return new PortRange(port, port);
  }

  /**
   * Returns a PortRange that matches any valid port (0-65535).
   *
   * @return a PortRange covering all ports
   */
  public static PortRange any() {
    return new PortRange(MIN_PORT, MAX_PORT);
  }

  /**
   * Checks if this range contains the given port.
   *
   * @param port the port to check
   * @return true if port is within this range (inclusive)
   */
  public boolean contains(int port) {
    return port >= start && port <= end;
  }

  @Override
  public String toString() {
    if (start == end) {
      return String.valueOf(start);
    }
    return start + "-" + end;
  }
}
