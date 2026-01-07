/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import java.net.IDN;
import java.util.Locale;

/**
 * Matches host strings against glob patterns for network capability enforcement.
 *
 * <h2>Pattern Syntax</h2>
 *
 * <ul>
 *   <li>{@code *} - matches exactly one DNS label (segment)
 *   <li>{@code **} - matches one or more DNS labels (any depth)
 *   <li>Literal segments match exactly (case-insensitive)
 * </ul>
 *
 * <h2>Examples</h2>
 *
 * <table border="1">
 *   <caption>Host pattern matching examples</caption>
 *   <tr><th>Pattern</th><th>Matches</th><th>Does NOT Match</th></tr>
 *   <tr><td>{@code *}</td><td>any host</td><td>-</td></tr>
 *   <tr><td>{@code example.com}</td><td>example.com</td><td>foo.example.com</td></tr>
 *   <tr><td>{@code *.example.com}</td><td>api.example.com</td><td>example.com, a.b.example.com</td></tr>
 *   <tr><td>{@code **.example.com}</td><td>api.example.com, a.b.c.example.com</td><td>example.com</td></tr>
 * </table>
 *
 * <h2>Normalization</h2>
 *
 * <p>Both host and pattern are normalized before matching:
 *
 * <ul>
 *   <li>Lowercase
 *   <li>Trim whitespace
 *   <li>Strip trailing dot ({@code example.com.} → {@code example.com})
 *   <li>Strip IPv6 brackets ({@code [::1]} → {@code ::1})
 *   <li>IDN to ASCII ({@code münchen.de} → {@code xn--mnchen-3ya.de})
 * </ul>
 */
public final class HostMatcher {

  private HostMatcher() {
    // Utility class
  }

  /**
   * Normalizes a host string for matching.
   *
   * @param host the host string (may be null)
   * @return normalized host, or empty string if null/blank
   */
  public static String normalize(String host) {
    if (host == null || host.isBlank()) {
      return "";
    }

    String h = host.trim().toLowerCase(Locale.ROOT);

    // Strip trailing dot (FQDN notation)
    if (h.endsWith(".")) {
      h = h.substring(0, h.length() - 1);
    }

    // Strip IPv6 brackets
    if (h.startsWith("[") && h.endsWith("]")) {
      h = h.substring(1, h.length() - 1);
    }

    // Convert IDN to ASCII (Punycode)
    try {
      h = IDN.toASCII(h, IDN.ALLOW_UNASSIGNED);
    } catch (IllegalArgumentException e) {
      // Keep as-is if IDN conversion fails
    }

    return h;
  }

  /**
   * Matches a host against a glob pattern.
   *
   * <p>Both host and pattern are normalized before matching.
   *
   * @param host the host to match (hostname or IP address)
   * @param pattern the glob pattern
   * @return true if host matches pattern
   */
  public static boolean matches(String host, String pattern) {
    String normalizedHost = normalize(host);
    String normalizedPattern = normalize(pattern);

    // "*" matches any host
    if ("*".equals(normalizedPattern)) {
      return true;
    }

    // Empty/null host only matches "*"
    if (normalizedHost.isEmpty()) {
      return false;
    }

    String[] hostSegments = normalizedHost.split("\\.");
    String[] patternSegments = normalizedPattern.split("\\.");

    return matchSegments(hostSegments, 0, patternSegments, 0);
  }

  /**
   * Recursively matches host segments against pattern segments.
   *
   * @param host host segments
   * @param hi current host index
   * @param pattern pattern segments
   * @param pi current pattern index
   * @return true if remaining segments match
   */
  private static boolean matchSegments(String[] host, int hi, String[] pattern, int pi) {
    // Base case: both exhausted - match!
    if (hi == host.length && pi == pattern.length) {
      return true;
    }

    // Pattern exhausted but host has more - no match
    if (pi == pattern.length) {
      return false;
    }

    // Host exhausted but pattern has more - no match
    // (** requires one-or-more segments, so we can't match with zero remaining)
    if (hi == host.length) {
      return false;
    }

    String p = pattern[pi];

    if ("**".equals(p)) {
      // ** matches one or more segments
      // Try matching 1, 2, 3, ... segments
      for (int skip = 1; hi + skip <= host.length; skip++) {
        if (matchSegments(host, hi + skip, pattern, pi + 1)) {
          return true;
        }
      }
      return false;
    } else if ("*".equals(p)) {
      // * matches exactly one segment
      return matchSegments(host, hi + 1, pattern, pi + 1);
    } else {
      // Literal segment - must match exactly
      if (!host[hi].equals(p)) {
        return false;
      }
      return matchSegments(host, hi + 1, pattern, pi + 1);
    }
  }
}
