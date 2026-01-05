/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for {@link PortRange}. */
class PortRangeTest {

  @Nested
  @DisplayName("parse()")
  class ParseTests {

    @Test
    @DisplayName("parses single port")
    void parsesSinglePort() {
      PortRange range = PortRange.parse("443");
      assertThat(range.start()).isEqualTo(443);
      assertThat(range.end()).isEqualTo(443);
    }

    @Test
    @DisplayName("parses port range")
    void parsesRange() {
      PortRange range = PortRange.parse("80-443");
      assertThat(range.start()).isEqualTo(80);
      assertThat(range.end()).isEqualTo(443);
    }

    @Test
    @DisplayName("parses port 0")
    void parsesPortZero() {
      PortRange range = PortRange.parse("0");
      assertThat(range.start()).isEqualTo(0);
      assertThat(range.end()).isEqualTo(0);
    }

    @Test
    @DisplayName("parses full range")
    void parsesFullRange() {
      PortRange range = PortRange.parse("0-65535");
      assertThat(range.start()).isEqualTo(0);
      assertThat(range.end()).isEqualTo(65535);
    }

    @Test
    @DisplayName("rejects range with spaces")
    void rejectsRangeWithSpaces() {
      assertThatThrownBy(() -> PortRange.parse("80 - 443"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid port number");
    }

    @Test
    @DisplayName("rejects leading whitespace")
    void rejectsLeadingWhitespace() {
      assertThatThrownBy(() -> PortRange.parse(" 443"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("whitespace");
    }

    @Test
    @DisplayName("rejects trailing whitespace")
    void rejectsTrailingWhitespace() {
      assertThatThrownBy(() -> PortRange.parse("443 "))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("whitespace");
    }

    @Test
    @DisplayName("rejects reversed range")
    void rejectsReversedRange() {
      assertThatThrownBy(() -> PortRange.parse("443-80"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("cannot be greater than end");
    }

    @Test
    @DisplayName("rejects negative port")
    void rejectsNegativePort() {
      assertThatThrownBy(() -> PortRange.parse("-1")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects port out of range")
    void rejectsOutOfRange() {
      assertThatThrownBy(() -> PortRange.parse("70000"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("out of range");
    }

    @Test
    @DisplayName("rejects invalid format - letters")
    void rejectsLetters() {
      assertThatThrownBy(() -> PortRange.parse("abc"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid port number");
    }

    @Test
    @DisplayName("rejects invalid format - trailing dash")
    void rejectsTrailingDash() {
      assertThatThrownBy(() -> PortRange.parse("80-"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("ends with dash");
    }

    @Test
    @DisplayName("rejects invalid format - leading dash for range")
    void rejectsLeadingDashRange() {
      assertThatThrownBy(() -> PortRange.parse("-443"))
          .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects null")
    void rejectsNull() {
      assertThatThrownBy(() -> PortRange.parse(null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null or empty");
    }

    @Test
    @DisplayName("rejects empty string")
    void rejectsEmpty() {
      assertThatThrownBy(() -> PortRange.parse(""))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("null or empty");
    }
  }

  @Nested
  @DisplayName("single()")
  class SingleTests {

    @Test
    @DisplayName("creates range for single port")
    void createsSinglePort() {
      PortRange range = PortRange.single(8080);
      assertThat(range.start()).isEqualTo(8080);
      assertThat(range.end()).isEqualTo(8080);
    }

    @Test
    @DisplayName("rejects invalid port")
    void rejectsInvalidPort() {
      assertThatThrownBy(() -> PortRange.single(-1)).isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> PortRange.single(70000))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Nested
  @DisplayName("any()")
  class AnyTests {

    @Test
    @DisplayName("covers full port range")
    void coversFullRange() {
      PortRange range = PortRange.any();
      assertThat(range.start()).isEqualTo(0);
      assertThat(range.end()).isEqualTo(65535);
    }
  }

  @Nested
  @DisplayName("contains()")
  class ContainsTests {

    @Test
    @DisplayName("returns true for port in range")
    void containsInRange() {
      PortRange range = PortRange.parse("80-443");
      assertThat(range.contains(80)).isTrue();
      assertThat(range.contains(200)).isTrue();
      assertThat(range.contains(443)).isTrue();
    }

    @Test
    @DisplayName("returns false for port out of range")
    void doesNotContainOutOfRange() {
      PortRange range = PortRange.parse("80-443");
      assertThat(range.contains(79)).isFalse();
      assertThat(range.contains(444)).isFalse();
      assertThat(range.contains(0)).isFalse();
      assertThat(range.contains(65535)).isFalse();
    }

    @Test
    @DisplayName("any range contains all ports")
    void anyContainsAll() {
      PortRange range = PortRange.any();
      assertThat(range.contains(0)).isTrue();
      assertThat(range.contains(80)).isTrue();
      assertThat(range.contains(443)).isTrue();
      assertThat(range.contains(65535)).isTrue();
    }

    @Test
    @DisplayName("single port range only contains that port")
    void singleContainsOnlyOne() {
      PortRange range = PortRange.single(8080);
      assertThat(range.contains(8080)).isTrue();
      assertThat(range.contains(8079)).isFalse();
      assertThat(range.contains(8081)).isFalse();
    }
  }

  @Nested
  @DisplayName("toString()")
  class ToStringTests {

    @Test
    @DisplayName("formats single port")
    void formatsSingle() {
      assertThat(PortRange.single(443).toString()).isEqualTo("443");
    }

    @Test
    @DisplayName("formats range")
    void formatsRange() {
      assertThat(PortRange.parse("80-443").toString()).isEqualTo("80-443");
    }
  }
}
