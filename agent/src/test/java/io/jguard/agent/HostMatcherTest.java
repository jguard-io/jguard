/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package io.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for {@link HostMatcher}. */
class HostMatcherTest {

  @Nested
  @DisplayName("Single-level wildcard (*)")
  class SingleLevelWildcardTests {

    @Test
    @DisplayName("*.example.com matches api.example.com")
    void matchesSingleSubdomain() {
      assertThat(HostMatcher.matches("api.example.com", "*.example.com")).isTrue();
    }

    @Test
    @DisplayName("*.example.com does NOT match example.com")
    void doesNotMatchBaseWithStar() {
      assertThat(HostMatcher.matches("example.com", "*.example.com")).isFalse();
    }

    @Test
    @DisplayName("*.example.com does NOT match a.b.example.com")
    void doesNotMatchTooDeep() {
      assertThat(HostMatcher.matches("a.b.example.com", "*.example.com")).isFalse();
    }

    @Test
    @DisplayName("api.*.example.com matches api.foo.example.com")
    void internalWildcardMatches() {
      assertThat(HostMatcher.matches("api.foo.example.com", "api.*.example.com")).isTrue();
    }

    @Test
    @DisplayName("api.*.example.com does NOT match api.example.com")
    void internalWildcardRequiresSegment() {
      assertThat(HostMatcher.matches("api.example.com", "api.*.example.com")).isFalse();
    }

    @Test
    @DisplayName("api.*.example.com does NOT match api.x.y.example.com")
    void internalWildcardMatchesOnlyOne() {
      assertThat(HostMatcher.matches("api.x.y.example.com", "api.*.example.com")).isFalse();
    }
  }

  @Nested
  @DisplayName("Multi-level wildcard (**)")
  class MultiLevelWildcardTests {

    @Test
    @DisplayName("**.example.com matches api.example.com")
    void matchesSingleLevel() {
      assertThat(HostMatcher.matches("api.example.com", "**.example.com")).isTrue();
    }

    @Test
    @DisplayName("**.example.com matches a.b.c.example.com")
    void matchesMultipleLevels() {
      assertThat(HostMatcher.matches("a.b.c.example.com", "**.example.com")).isTrue();
    }

    @Test
    @DisplayName("**.example.com does NOT match example.com")
    void doesNotMatchBaseDomain() {
      // ** requires one-or-more segments
      assertThat(HostMatcher.matches("example.com", "**.example.com")).isFalse();
    }

    @Test
    @DisplayName("api.**.example.com matches api.foo.example.com")
    void internalDoubleStarMatchesOne() {
      assertThat(HostMatcher.matches("api.foo.example.com", "api.**.example.com")).isTrue();
    }

    @Test
    @DisplayName("api.**.example.com matches api.x.y.z.example.com")
    void internalDoubleStarMatchesMany() {
      assertThat(HostMatcher.matches("api.x.y.z.example.com", "api.**.example.com")).isTrue();
    }

    @Test
    @DisplayName("api.**.example.com does NOT match api.example.com")
    void internalDoubleStarRequiresOneOrMore() {
      assertThat(HostMatcher.matches("api.example.com", "api.**.example.com")).isFalse();
    }
  }

  @Nested
  @DisplayName("Universal wildcard")
  class UniversalWildcardTests {

    @Test
    @DisplayName("* matches any hostname")
    void starMatchesAnyHostname() {
      assertThat(HostMatcher.matches("example.com", "*")).isTrue();
      assertThat(HostMatcher.matches("api.example.com", "*")).isTrue();
      assertThat(HostMatcher.matches("a.b.c.d.example.com", "*")).isTrue();
    }

    @Test
    @DisplayName("* matches IP address")
    void starMatchesIpAddress() {
      assertThat(HostMatcher.matches("93.184.216.34", "*")).isTrue();
      assertThat(HostMatcher.matches("::1", "*")).isTrue();
    }

    @Test
    @DisplayName("** alone matches any hostname with 1+ segments (but not null/empty)")
    void doubleStarAloneMatchesAnyNonEmpty() {
      // ** as a standalone pattern matches any host with at least one segment
      // This is similar to * but with key difference: * matches null/empty, ** doesn't
      assertThat(HostMatcher.matches("example.com", "**")).isTrue();
      assertThat(HostMatcher.matches("api.example.com", "**")).isTrue();
      assertThat(HostMatcher.matches("localhost", "**")).isTrue();

      // Unlike *, ** does NOT match null/empty
      assertThat(HostMatcher.matches(null, "**")).isFalse();
      assertThat(HostMatcher.matches("", "**")).isFalse();
    }
  }

  @Nested
  @DisplayName("Exact match")
  class ExactMatchTests {

    @Test
    @DisplayName("exact pattern matches exact host")
    void exactMatch() {
      assertThat(HostMatcher.matches("example.com", "example.com")).isTrue();
      assertThat(HostMatcher.matches("api.example.com", "api.example.com")).isTrue();
    }

    @Test
    @DisplayName("exact pattern does NOT match subdomain")
    void exactDoesNotMatchSubdomain() {
      assertThat(HostMatcher.matches("api.example.com", "example.com")).isFalse();
    }

    @Test
    @DisplayName("exact pattern does NOT match parent domain")
    void exactDoesNotMatchParent() {
      assertThat(HostMatcher.matches("example.com", "api.example.com")).isFalse();
    }
  }

  @Nested
  @DisplayName("Case insensitivity")
  class CaseInsensitivityTests {

    @Test
    @DisplayName("matching is case-insensitive for host")
    void caseInsensitiveHost() {
      assertThat(HostMatcher.matches("API.Example.COM", "*.example.com")).isTrue();
    }

    @Test
    @DisplayName("matching is case-insensitive for pattern")
    void caseInsensitivePattern() {
      assertThat(HostMatcher.matches("api.example.com", "*.EXAMPLE.COM")).isTrue();
    }

    @Test
    @DisplayName("exact match is case-insensitive")
    void caseInsensitiveExact() {
      assertThat(HostMatcher.matches("EXAMPLE.COM", "example.com")).isTrue();
    }
  }

  @Nested
  @DisplayName("Normalization")
  class NormalizationTests {

    @Test
    @DisplayName("host with trailing dot is normalized")
    void trailingDotNormalized() {
      assertThat(HostMatcher.matches("api.example.com.", "*.example.com")).isTrue();
    }

    @Test
    @DisplayName("pattern with trailing dot is normalized")
    void patternTrailingDotNormalized() {
      assertThat(HostMatcher.matches("api.example.com", "*.example.com.")).isTrue();
    }

    @Test
    @DisplayName("IPv6 brackets are stripped")
    void ipv6BracketsStripped() {
      assertThat(HostMatcher.normalize("[::1]")).isEqualTo("::1");
      assertThat(HostMatcher.matches("[::1]", "::1")).isTrue();
    }

    @Test
    @DisplayName("whitespace is trimmed")
    void whitespaceTrimmed() {
      assertThat(HostMatcher.normalize("  example.com  ")).isEqualTo("example.com");
    }

    @Test
    @DisplayName("null host returns empty string")
    void nullReturnsEmpty() {
      assertThat(HostMatcher.normalize(null)).isEqualTo("");
    }

    @Test
    @DisplayName("blank host returns empty string")
    void blankReturnsEmpty() {
      assertThat(HostMatcher.normalize("   ")).isEqualTo("");
    }
  }

  @Nested
  @DisplayName("Null and empty host handling")
  class NullAndEmptyTests {

    @Test
    @DisplayName("null host matches only *")
    void nullMatchesOnlyStar() {
      assertThat(HostMatcher.matches(null, "*")).isTrue();
      assertThat(HostMatcher.matches(null, "example.com")).isFalse();
      assertThat(HostMatcher.matches(null, "*.example.com")).isFalse();
    }

    @Test
    @DisplayName("empty host matches only *")
    void emptyMatchesOnlyStar() {
      assertThat(HostMatcher.matches("", "*")).isTrue();
      assertThat(HostMatcher.matches("", "example.com")).isFalse();
    }

    @Test
    @DisplayName("blank host matches only *")
    void blankMatchesOnlyStar() {
      assertThat(HostMatcher.matches("   ", "*")).isTrue();
      assertThat(HostMatcher.matches("   ", "example.com")).isFalse();
    }
  }

  @Nested
  @DisplayName("IP address handling")
  class IpAddressTests {

    @Test
    @DisplayName("* matches IPv4 address")
    void starMatchesIpv4() {
      assertThat(HostMatcher.matches("93.184.216.34", "*")).isTrue();
    }

    @Test
    @DisplayName("* matches IPv6 address")
    void starMatchesIpv6() {
      assertThat(HostMatcher.matches("2606:2800:220:1:248:1893:25c8:1946", "*")).isTrue();
    }

    @Test
    @DisplayName("exact IPv4 match works")
    void exactIpv4Match() {
      assertThat(HostMatcher.matches("93.184.216.34", "93.184.216.34")).isTrue();
    }

    @Test
    @DisplayName("IP wildcard pattern works for octets")
    void ipWildcardPattern() {
      // IP addresses are dot-separated, so segment matching works
      assertThat(HostMatcher.matches("192.168.1.100", "192.168.*.*")).isTrue();
      assertThat(HostMatcher.matches("10.0.0.1", "192.168.*.*")).isFalse();
    }

    @Test
    @DisplayName("IP pattern does NOT match hostname")
    void ipPatternDoesNotMatchHostname() {
      assertThat(HostMatcher.matches("example.com", "93.184.*.*")).isFalse();
    }
  }

  @Nested
  @DisplayName("Edge cases")
  class EdgeCaseTests {

    @Test
    @DisplayName("single segment host")
    void singleSegmentHost() {
      assertThat(HostMatcher.matches("localhost", "localhost")).isTrue();
      assertThat(HostMatcher.matches("localhost", "*")).isTrue();
      assertThat(HostMatcher.matches("localhost", "*.example.com")).isFalse();
    }

    @Test
    @DisplayName("deeply nested host")
    void deeplyNestedHost() {
      String deep = "a.b.c.d.e.f.g.example.com";
      assertThat(HostMatcher.matches(deep, "**.example.com")).isTrue();
      assertThat(HostMatcher.matches(deep, "*.example.com")).isFalse();
    }

    @Test
    @DisplayName("pattern longer than host")
    void patternLongerThanHost() {
      assertThat(HostMatcher.matches("example.com", "api.sub.example.com")).isFalse();
    }

    @Test
    @DisplayName("host longer than pattern")
    void hostLongerThanPattern() {
      assertThat(HostMatcher.matches("api.sub.example.com", "example.com")).isFalse();
    }

    @Test
    @DisplayName("** at end of pattern")
    void doubleStarAtEnd() {
      assertThat(HostMatcher.matches("api.example.com", "api.**")).isTrue();
      assertThat(HostMatcher.matches("api.a.b.c", "api.**")).isTrue();
      assertThat(HostMatcher.matches("api", "api.**")).isFalse(); // ** needs at least one
    }

    @Test
    @DisplayName("multiple * wildcards")
    void multipleStarWildcards() {
      assertThat(HostMatcher.matches("a.b.c", "*.*.*")).isTrue();
      assertThat(HostMatcher.matches("a.b", "*.*.*")).isFalse();
      assertThat(HostMatcher.matches("a.b.c.d", "*.*.*")).isFalse();
    }
  }
}
