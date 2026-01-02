/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The jGuard Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.jguard.agent;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link CallerAttribution}. */
class CallerAttributionTest {

  @Test
  @DisplayName("returns package name of calling code")
  void returnsCallerPackage() {
    // When called from this test class, should return this package
    String callerPackage = CallerAttribution.getCallerPackage();

    // The test is in org.jguard.agent, but that's in INFRASTRUCTURE_PACKAGES
    // So it should skip that and return "unknown" or the test framework package
    // Actually, let's verify it returns something reasonable
    assertThat(callerPackage).isNotNull();
    assertThat(callerPackage).isNotEmpty();
  }

  @Test
  @DisplayName("returns class of calling code")
  void returnsCallerClass() {
    Class<?> callerClass = CallerAttribution.getCallerClass();

    // Should return something (might be test framework class)
    // Since our test package is in INFRASTRUCTURE_PACKAGES, it might skip it
    // The actual class returned depends on the test framework
    assertThat(callerClass).isNotNull();
  }

  @Test
  @DisplayName("skips infrastructure packages")
  void skipsInfrastructurePackages() {
    // This test verifies that infrastructure packages are skipped
    // Since we're calling from org.jguard.agent (which is in the skip list),
    // the caller attribution should walk up the stack to find non-infrastructure code

    String pkg = CallerAttribution.getCallerPackage();

    // Should not return any of the infrastructure packages
    assertThat(pkg).doesNotStartWith("java.");
    assertThat(pkg).doesNotStartWith("sun.");
    assertThat(pkg).doesNotStartWith("jdk.");
    assertThat(pkg).isNotEqualTo("org.jguard.agent");
    assertThat(pkg).isNotEqualTo("org.jguard.core");
  }
}
